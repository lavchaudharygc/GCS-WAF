-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  geoip.lua
--  GeoIP country lookup using MaxMind GeoLite2 MMDB
--  Falls back gracefully if DB file is missing
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx    = ngx
local shared = ngx.shared

local MMDB_PATH       = "/etc/nginx/geoip/GeoLite2-Country.mmdb"
local CACHE_TTL       = 3600  -- cache lookups for 1 hour
local BLOCKED_COUNTRIES = {}  -- populate from env or config

-- Check if country blocking is configured
local blocked_env = os.getenv("GCS_BLOCKED_COUNTRIES") or ""
for country in blocked_env:gmatch("[A-Z][A-Z]") do
    BLOCKED_COUNTRIES[country] = true
end

-- ── Lazy-load mmdb library ────────────────────────────────────────────────────
local _mmdb_db = nil
local _mmdb_loaded = false

local function get_db()
    if _mmdb_loaded then return _mmdb_db end
    _mmdb_loaded = true

    -- Try luajit-geoip (mmdb)
    local ok, geoip = pcall(require, "geoip.mmdb")
    if ok then
        local db, err = geoip.load_database(MMDB_PATH)
        if db then
            _mmdb_db = db
            ngx.log(ngx.INFO, "GCS-WAF GeoIP: loaded MMDB from " .. MMDB_PATH)
        else
            ngx.log(ngx.WARN, "GCS-WAF GeoIP: MMDB load failed: " .. tostring(err))
        end
        return _mmdb_db
    end

    ngx.log(ngx.WARN, "GCS-WAF GeoIP: mmdb library not available, GeoIP disabled")
    return nil
end

-- ── Public: lookup country for an IP ────────────────────────────────────────
function _M.lookup(ip)
    if not ip or ip == "" then return "XX" end

    -- Cache hit
    local cache = shared.gcs_geo_cache
    local cached = cache:get(ip)
    if cached then return cached end

    local db = get_db()
    if not db then
        cache:set(ip, "XX", CACHE_TTL)
        return "XX"
    end

    local ok, result = pcall(function()
        return db:lookup_value(ip, "country", "iso_code")
    end)

    local country = (ok and result) or "XX"
    cache:set(ip, country, CACHE_TTL)
    return country
end

-- ── Public: check if country is blocked ──────────────────────────────────────
function _M.is_blocked_country(ip)
    if not next(BLOCKED_COUNTRIES) then return false end
    local country = _M.lookup(ip)
    return BLOCKED_COUNTRIES[country] == true, country
end

return _M
