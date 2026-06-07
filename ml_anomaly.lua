-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  ml_anomaly.lua
--  Lightweight ML anomaly detection — no external libs required.
--  Uses statistical Z-score + feature vector comparison (Isolation Forest lite).
--  Learns normal traffic patterns and flags deviations.
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx    = ngx
local shared = ngx.shared

-- ── Feature extraction ────────────────────────────────────────────────────────
-- Extracts a numeric feature vector from the current request

local function extract_features()
    local uri    = ngx.var.request_uri or "/"
    local method = ngx.var.request_method or "GET"
    local ua     = ngx.var.http_user_agent or ""
    local body   = ""

    if method == "POST" or method == "PUT" then
        ngx.req.read_body()
        body = ngx.req.get_body_data() or ""
    end

    local args = ngx.req.get_uri_args(50)
    local arg_count = 0
    local arg_len   = 0
    for k, v in pairs(args) do
        arg_count = arg_count + 1
        local val = type(v) == "table" and table.concat(v, "") or tostring(v)
        arg_len = arg_len + #val + #k
    end

    -- Entropy helper (measure of randomness in a string)
    local function entropy(s)
        if #s == 0 then return 0 end
        local freq = {}
        for i = 1, #s do
            local c = s:sub(i,i)
            freq[c] = (freq[c] or 0) + 1
        end
        local h = 0
        for _, f in pairs(freq) do
            local p = f / #s
            h = h - p * (math.log(p) / math.log(2))
        end
        return h
    end

    -- Count special chars (indicator of injection)
    local function count_special(s)
        local n = 0
        for c in s:gmatch("[<>'\";(){}|&$`!%[%]]") do n = n + 1 end
        return n
    end

    local features = {
        uri_length    = #uri,
        uri_entropy   = entropy(uri),
        uri_special   = count_special(uri),
        uri_dirs      = select(2, uri:gsub("/", "/")),  -- depth
        arg_count     = arg_count,
        arg_total_len = arg_len,
        arg_entropy   = entropy(ngx.var.query_string or ""),
        body_length   = #body,
        body_entropy  = entropy(body:sub(1, 512)),
        body_special  = count_special(body:sub(1, 512)),
        ua_length     = #ua,
        is_post       = method == "POST" and 1 or 0,
        method_num    = ({ GET=0, POST=1, PUT=2, DELETE=3, PATCH=4, HEAD=5, OPTIONS=6 })[method] or 7,
    }
    return features
end

-- ── Stats tracker using Welford's online algorithm ───────────────────────────
-- Tracks mean + variance per feature without storing all data points

local FEATURE_NAMES = {
    "uri_length", "uri_entropy", "uri_special", "uri_dirs",
    "arg_count", "arg_total_len", "arg_entropy",
    "body_length", "body_entropy", "body_special",
    "ua_length", "is_post", "method_num",
}

local function get_stats(feature)
    local ml = shared.gcs_ml_features
    local n    = tonumber(ml:get(feature .. ":n")    or 0)
    local mean = tonumber(ml:get(feature .. ":mean") or 0)
    local m2   = tonumber(ml:get(feature .. ":m2")   or 0)
    return n, mean, m2
end

local function update_stats(feature, value)
    local ml = shared.gcs_ml_features
    local n, mean, m2 = get_stats(feature)
    n    = n + 1
    local delta  = value - mean
    mean = mean + delta / n
    local delta2 = value - mean
    m2   = m2 + delta * delta2
    ml:set(feature .. ":n",    n,    0)
    ml:set(feature .. ":mean", mean, 0)
    ml:set(feature .. ":m2",   m2,   0)
end

local function get_stddev(feature)
    local n, mean, m2 = get_stats(feature)
    if n < 30 then return 0, 0 end  -- not enough data yet
    local variance = m2 / (n - 1)
    return mean, math.sqrt(variance)
end

-- ── Z-score anomaly detection ─────────────────────────────────────────────────
local function z_score_anomaly(features)
    local anomaly_score = 0
    local anomalies     = {}

    for _, fname in ipairs(FEATURE_NAMES) do
        local val  = features[fname] or 0
        local mean, stddev = get_stddev(fname)

        if stddev > 0 then
            local z = math.abs(val - mean) / stddev
            if z > 4.0 then      -- 4-sigma = very anomalous
                anomaly_score = anomaly_score + 0.3
                table.insert(anomalies, fname .. "(" .. string.format("%.1f", z) .. "σ)")
            elseif z > 3.0 then  -- 3-sigma = suspicious
                anomaly_score = anomaly_score + 0.1
            end
        end
    end

    return anomaly_score, anomalies
end

-- ── Public: score current request ────────────────────────────────────────────
function _M.score()
    local ml = shared.gcs_ml_features
    local n  = tonumber(ml:get("total_requests") or 0)

    -- Don't score until we have enough baseline data
    if n < 100 then return false, 0 end

    local features      = extract_features()
    local score, why    = z_score_anomaly(features)

    if #why > 0 then
        ngx.log(ngx.WARN, "GCS-WAF ML: anomalies detected: " .. table.concat(why, ", ") ..
                           " score=" .. string.format("%.2f", score))
    end

    return score > 0.85, score
end

-- ── Public: record a request as "normal" for baseline learning ───────────────
function _M.record_request()
    -- Only record if WAF didn't flag this request
    if ngx.var.waf_action == "block" then return end

    local ml = shared.gcs_ml_features
    ml:incr("total_requests", 1, 0)

    local features = extract_features()
    for _, fname in ipairs(FEATURE_NAMES) do
        local val = features[fname] or 0
        update_stats(fname, val)
    end
end

-- ── Public: get model stats (for dashboard) ───────────────────────────────────
function _M.get_stats()
    local ml = shared.gcs_ml_features
    local n  = tonumber(ml:get("total_requests") or 0)
    local stat = { total_requests = n, features = {} }
    for _, fname in ipairs(FEATURE_NAMES) do
        local mean, stddev = get_stddev(fname)
        stat.features[fname] = {
            mean   = string.format("%.2f", mean),
            stddev = string.format("%.2f", stddev),
        }
    end
    return stat
end

return _M
