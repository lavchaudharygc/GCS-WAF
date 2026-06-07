-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  behavior.lua
--  Behavior scoring + rate limiting. Redis-backed with in-memory fallback.
--  FIX: container no longer crashes if Redis is down.
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx     = ngx
local shared  = ngx.shared

-- ── Config ────────────────────────────────────────────────────────────────────
local REDIS_HOST    = os.getenv("REDIS_HOST") or "gcs-waf-redis"
local REDIS_PORT    = tonumber(os.getenv("REDIS_PORT") or "6379")
local REDIS_TIMEOUT = 1000  -- ms

-- Thresholds
local RATE_WINDOW   = 60    -- seconds
local RATE_LIMIT    = 120   -- requests per window
local BURST_LIMIT   = 30    -- requests per 5s (burst)
local SCORE_TTL     = 3600  -- behavior score expiry (s)

-- Score penalty table
local PENALTIES = {
    high_request_rate  = 30,
    burst_traffic      = 25,
    bad_error_ratio    = 20,
    suspicious_path    = 15,
    repeated_404       = 20,
    user_agent_change  = 10,
    no_referer_post    = 10,
}

-- ── Redis connection helper (non-fatal) ───────────────────────────────────────
local redis_lib
local function get_redis()
    if not redis_lib then
        local ok
        ok, redis_lib = pcall(require, "resty.redis")
        if not ok then return nil, "resty.redis not available" end
    end
    local r, err = redis_lib:new()
    if not r then return nil, err end
    r:set_timeout(REDIS_TIMEOUT)
    local ok2, err2 = r:connect(REDIS_HOST, REDIS_PORT)
    if not ok2 then
        return nil, "Redis connect failed: " .. tostring(err2)
    end
    return r, nil
end

-- ── Get/set score using shared dict (fast path) + Redis (persistent path) ────
local function get_score(ip)
    local scores = shared.gcs_ip_scores
    local v = scores:get(ip)
    if v then return tonumber(v) or 0 end
    -- Try Redis as fallback
    local r, err = get_redis()
    if r then
        local val, rerr = r:get("gcs:score:" .. ip)
        r:set_keepalive(10000, 100)
        if val and val ~= ngx.null then
            local n = tonumber(val) or 0
            scores:set(ip, n, SCORE_TTL)
            return n
        end
    end
    return 0
end

local function add_score(ip, delta, reason)
    local scores  = shared.gcs_ip_scores
    local current = get_score(ip)
    local new_val = current + delta
    scores:set(ip, new_val, SCORE_TTL)

    -- Also push to Redis async (non-blocking via ngx.timer.at)
    local ip_copy = ip
    local val_copy = new_val
    ngx.timer.at(0, function()
        local r, err = get_redis()
        if r then
            r:setex("gcs:score:" .. ip_copy, SCORE_TTL, val_copy)
            r:set_keepalive(10000, 100)
        end
    end)

    return new_val, reason
end

-- ── Rate limit check using sliding window ────────────────────────────────────
local function check_rate_limit(ip)
    local rl    = shared.gcs_rate_limit
    local now   = ngx.time()
    local key   = ip .. ":" .. math.floor(now / RATE_WINDOW)
    local burst_key = ip .. ":burst:" .. math.floor(now / 5)

    -- increment counters
    local count, ferr = rl:incr(key, 1)
    if not count then
        rl:set(key, 1, RATE_WINDOW * 2)
        count = 1
    end
    if count == 1 then rl:expire(key, RATE_WINDOW * 2) end

    local burst, _ = rl:incr(burst_key, 1)
    if not burst then
        rl:set(burst_key, 1, 10)
        burst = 1
    end

    if count > RATE_LIMIT then
        return true, "high_request_rate", PENALTIES.high_request_rate
    end
    if burst > BURST_LIMIT then
        return true, "burst_traffic", PENALTIES.burst_traffic
    end
    return false, nil, 0
end

-- ── Behavioral heuristics ────────────────────────────────────────────────────
local function behavioral_checks(ip)
    local penalty = 0
    local reason  = nil
    local uri     = ngx.var.request_uri or ""
    local method  = ngx.var.request_method or "GET"
    local ua      = ngx.var.http_user_agent or ""
    local ref     = ngx.var.http_referer or ""

    -- POST without referer (often bots / scanners)
    if method == "POST" and ref == "" then
        penalty = penalty + PENALTIES.no_referer_post
        reason  = reason or "no_referer_post"
    end

    -- Suspicious path patterns
    local sus_paths = { "wp-admin", "phpmyadmin", ".env", ".git", "actuator", "admin", "console", "manager" }
    for _, p in ipairs(sus_paths) do
        if uri:lower():find(p, 1, true) then
            penalty = penalty + PENALTIES.suspicious_path
            reason  = reason or "suspicious_path"
            break
        end
    end

    -- Track 404s per IP
    -- This is done in log_request below and scored on next request
    local rl       = shared.gcs_rate_limit
    local err_key  = ip .. ":404s"
    local err_count = tonumber(rl:get(err_key) or 0)
    if err_count > 10 then
        penalty = penalty + PENALTIES.repeated_404
        reason  = reason or "repeated_404"
    end

    return penalty, reason
end

-- ── Public: score a request ───────────────────────────────────────────────────
function _M.score_request()
    local ip      = ngx.var.remote_addr or "0.0.0.0"

    -- Rate limit first (fast path)
    local rate_blocked, rate_reason, rate_penalty = check_rate_limit(ip)
    if rate_blocked then
        local new_score = add_score(ip, rate_penalty, rate_reason)
        return rate_penalty, rate_reason
    end

    -- Behavioral checks
    local bhv_penalty, bhv_reason = behavioral_checks(ip)

    -- Accumulated behavior score
    local current = get_score(ip)
    if bhv_penalty > 0 then
        add_score(ip, bhv_penalty, bhv_reason)
    end

    -- Return penalty from this request only (caller adds to WAF score)
    return bhv_penalty, bhv_reason
end

-- ── Public: log request outcome (for 404 tracking) ───────────────────────────
function _M.log_request()
    local ip     = ngx.var.remote_addr or "0.0.0.0"
    local status = tonumber(ngx.var.status or 0)
    local rl     = shared.gcs_rate_limit

    if status == 404 then
        local key = ip .. ":404s"
        local n, err = rl:incr(key, 1)
        if not n then rl:set(key, 1, 600) end
    end
end

-- ── Public: flush to Redis (called by timer) ──────────────────────────────────
function _M.flush_to_redis()
    -- In this design scores are already pushed on write; this is a no-op
    -- but can be used for batch operations if needed
    return true
end

-- ── Public: get score for an IP (for dashboard) ───────────────────────────────
function _M.get_ip_score(ip)
    return get_score(ip)
end

return _M
