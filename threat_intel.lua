-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  threat_intel.lua
--  Auto-updating threat intelligence: Spamhaus DROP, Emerging Threats,
--  Tor exit nodes, custom feeds. Redis + shared dict backed.
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx    = ngx
local shared = ngx.shared
local http   -- lazy-load resty.http

-- ── Feed definitions ──────────────────────────────────────────────────────────
local FEEDS = {
    {
        name     = "spamhaus_drop",
        url      = "https://www.spamhaus.org/drop/drop.txt",
        ttl      = 86400,  -- refresh every 24h
        parser   = "cidr",
    },
    {
        name     = "spamhaus_edrop",
        url      = "https://www.spamhaus.org/drop/edrop.txt",
        ttl      = 86400,
        parser   = "cidr",
    },
    {
        name     = "emerging_threats",
        url      = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        ttl      = 43200,  -- refresh every 12h
        parser   = "ip_list",
    },
    {
        name     = "tor_exit",
        url      = "https://check.torproject.org/torbulkexitlist",
        ttl      = 3600,   -- refresh hourly
        parser   = "ip_list",
    },
}

-- CIDR matching (pure Lua, no C deps)
local function ip_to_num(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return  tonumber(a)*16777216 + tonumber(b)*65536 + tonumber(c)*256 + tonumber(d)
end

local function cidr_match(ip, cidr)
    local net, bits = cidr:match("^([%d%.]+)/(%d+)$")
    if not net then return ip == cidr end
    local mask   = bits and (0xFFFFFFFF - (2^(32-tonumber(bits))-1)) or 0xFFFFFFFF
    local ip_n   = ip_to_num(ip)
    local net_n  = ip_to_num(net)
    if not ip_n or not net_n then return false end
    return (ip_n & mask) == (net_n & mask)
end

-- ── Feed parsers ──────────────────────────────────────────────────────────────
local parsers = {
    cidr = function(body)
        local entries = {}
        for line in body:gmatch("[^\n]+") do
            line = line:gsub("^%s+", ""):gsub("%s+$", "")
            if line ~= "" and not line:match("^;") and not line:match("^#") then
                local cidr = line:match("^([%d%.]+/%d+)")
                if cidr then table.insert(entries, cidr) end
            end
        end
        return entries
    end,
    ip_list = function(body)
        local entries = {}
        for line in body:gmatch("[^\n]+") do
            line = line:gsub("^%s+", ""):gsub("%s+$", "")
            if line ~= "" and not line:match("^#") then
                local ip = line:match("^(%d+%.%d+%.%d+%.%d+)")
                if ip then table.insert(entries, ip) end
            end
        end
        return entries
    end,
}

-- ── In-memory store ───────────────────────────────────────────────────────────
local _loaded_feeds = {}  -- { feed_name = { "1.2.3.0/24", ... } }

-- ── HTTP fetch helper ─────────────────────────────────────────────────────────
local function fetch_url(url)
    if not http then
        local ok
        ok, http = pcall(require, "resty.http")
        if not ok then return nil, "resty.http not available" end
    end
    local client = http.new()
    client:set_timeout(10000)
    local res, err = client:request_uri(url, {
        method  = "GET",
        headers = { ["User-Agent"] = "GCS-WAF/2.0 threat-intel-updater" },
        ssl_verify = false,
    })
    if not res then return nil, err end
    if res.status ~= 200 then
        return nil, "HTTP " .. res.status
    end
    return res.body, nil
end

-- ── Public: load feeds on startup ─────────────────────────────────────────────
function _M.load_feeds()
    local intel = shared.gcs_threat_intel
    -- Check if feeds were already loaded recently
    local last_load = intel:get("_last_load")
    if last_load and (ngx.time() - last_load) < 3600 then
        -- Restore from shared dict to memory
        for _, feed in ipairs(FEEDS) do
            local data = intel:get(feed.name)
            if data then
                local ok, entries = pcall(require("cjson").decode, data)
                if ok then _loaded_feeds[feed.name] = entries end
            end
        end
        return
    end

    _M.refresh_feeds()
end

-- ── Public: refresh feeds (called by timer) ───────────────────────────────────
function _M.refresh_feeds()
    local intel = shared.gcs_threat_intel
    local cjson_ok, cjson = pcall(require, "cjson")

    for _, feed in ipairs(FEEDS) do
        ngx.log(ngx.INFO, "GCS-WAF: refreshing feed " .. feed.name)
        local body, err = fetch_url(feed.url)
        if body then
            local parse_fn = parsers[feed.parser] or parsers.ip_list
            local entries  = parse_fn(body)
            _loaded_feeds[feed.name] = entries
            -- Persist to shared dict
            if cjson_ok then
                local encoded = cjson.encode(entries)
                intel:set(feed.name, encoded, feed.ttl * 2)
            end
            ngx.log(ngx.INFO, string.format(
                "GCS-WAF: loaded %d entries from %s", #entries, feed.name))
        else
            ngx.log(ngx.WARN, "GCS-WAF: failed to fetch " .. feed.name .. ": " .. tostring(err))
        end
    end

    intel:set("_last_load", ngx.time(), 7200)
end

-- ── Public: check IP against all feeds ────────────────────────────────────────
function _M.check_ip(ip)
    if not ip then return false end

    -- Fast path: check blocklist shared dict (dynamic runtime blocks)
    local bl = shared.gcs_blocklist
    if bl:get(ip) then
        return true, "dynamic_block"
    end

    -- Check loaded feeds
    for feed_name, entries in pairs(_loaded_feeds) do
        for _, entry in ipairs(entries) do
            if entry:find("/", 1, true) then
                if cidr_match(ip, entry) then
                    return true, feed_name
                end
            else
                if ip == entry then
                    return true, feed_name
                end
            end
        end
    end

    return false, nil
end

-- ── Public: dynamically block an IP ──────────────────────────────────────────
function _M.block_ip(ip, ttl, reason)
    local bl = shared.gcs_blocklist
    bl:set(ip, reason or "manual", ttl or 3600)
    ngx.log(ngx.WARN, "GCS-WAF: dynamic block added for " .. ip .. " reason:" .. (reason or "manual"))
end

-- ── Public: unblock an IP ─────────────────────────────────────────────────────
function _M.unblock_ip(ip)
    local bl = shared.gcs_blocklist
    bl:delete(ip)
end

-- ── Public: list all dynamically blocked IPs ─────────────────────────────────
function _M.list_blocked()
    local bl   = shared.gcs_blocklist
    local keys = bl:get_keys(200)
    local result = {}
    for _, k in ipairs(keys) do
        table.insert(result, { ip = k, reason = bl:get(k) })
    end
    return result
end

return _M
