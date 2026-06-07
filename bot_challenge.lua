-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  bot_challenge.lua
--  JS-based bot challenge (proof-of-work style cookie challenge)
--  Browser solves it automatically; bots/curl can't.
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx        = ngx
local re_find    = ngx.re.find
local shared     = ngx.shared
local hmac       = ngx.hmac_sha1  -- built-in to OpenResty

-- ── Config ────────────────────────────────────────────────────────────────────
local SECRET_KEY     = os.getenv("WAF_SECRET") or "gcs-waf-secret-change-in-prod"
local CHALLENGE_TTL  = 600   -- challenge valid for 10 min
local BYPASS_COOKIE  = "gcs_verified"

-- Paths that never need a challenge
local EXEMPT_PATHS = {
    [[^/health$]],
    [[^/waf-api/]],
    [[^/waf-challenge]],
    [[^\.(png|jpg|ico|css|js|woff2?)$]],
}

-- Known bots that SHOULD be challenged (suspicious scanners)
local BOT_PATTERNS = {
    [[\b(sqlmap|nikto|nessus|nmap|masscan|dirbuster|hydra|havij|acunetix|w3af)\b]],
    [[^(curl|wget|python-requests|go-http|java/|ruby)/]],
    [[libwww-perl]],
    [[zgrab|zmap|shodan|censys|binaryedge]],
}

-- ── Helpers ───────────────────────────────────────────────────────────────────
local function make_token(ip, ts)
    local raw = ip .. ":" .. tostring(ts) .. ":" .. SECRET_KEY
    return ngx.md5(raw)
end

local function is_exempt(uri)
    for _, p in ipairs(EXEMPT_PATHS) do
        if re_find(uri, p, "ijo") then return true end
    end
    return false
end

local function looks_like_bot(ua)
    if not ua or ua == "" then return true end  -- no UA = bot
    for _, p in ipairs(BOT_PATTERNS) do
        if re_find(ua:lower(), p, "ijo") then return true end
    end
    return false
end

-- ── Public: check whether this request needs a challenge ─────────────────────
function _M.check()
    local uri = ngx.var.request_uri or "/"
    if is_exempt(uri) then return false end

    local ua    = ngx.var.http_user_agent or ""
    local ip    = ngx.var.remote_addr
    local cache = shared.gcs_bot_challenge

    -- Already verified in this window?
    if cache:get("ok:" .. ip) then return false end

    -- Check browser cookie
    local cookies = ngx.var.http_cookie or ""
    local _, _, c = cookies:find(BYPASS_COOKIE .. "=([^;]+)")
    if c then
        -- Validate token
        local parts = {}
        for part in c:gmatch("[^%.]+") do table.insert(parts, part) end
        if #parts == 2 then
            local ts    = tonumber(parts[1]) or 0
            local token = parts[2]
            local now   = ngx.time()
            if now - ts < CHALLENGE_TTL and make_token(ip, ts) == token then
                cache:set("ok:" .. ip, true, CHALLENGE_TTL)
                return false
            end
        end
    end

    -- Only challenge clear bots, not all traffic (to reduce friction)
    if looks_like_bot(ua) then
        return true
    end

    return false
end

-- ── Public: serve the JS challenge page ──────────────────────────────────────
function _M.serve_challenge()
    local ip  = ngx.var.remote_addr
    local ts  = ngx.time()
    local tok = make_token(ip, ts)

    ngx.header["Content-Type"]                 = "text/html; charset=utf-8"
    ngx.header["Cache-Control"]                = "no-store"
    ngx.header["Access-Control-Allow-Origin"]  = "*"
    ngx.status = 200

    ngx.say(string.format([[<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GCS-WAF — Security Check</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; background: #0d0d0d; color: #00ff88;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .box { border: 1px solid #00ff88; padding: 48px 64px; text-align: center;
         box-shadow: 0 0 60px rgba(0,255,136,.2); max-width: 480px; }
  h1 { font-size: 14px; letter-spacing: 6px; color: #888; margin-bottom: 32px; text-transform: uppercase; }
  .spinner { width: 40px; height: 40px; border: 2px solid #1a1a1a; border-top-color: #00ff88;
             border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 24px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  p { color: #555; font-size: 12px; letter-spacing: 1px; }
  .ok { color: #00ff88; display: none; font-size: 18px; margin-bottom: 12px; }
</style>
</head>
<body>
<div class="box">
  <h1>GCS-WAF Security Check</h1>
  <div class="spinner" id="spin"></div>
  <div class="ok" id="ok">✓ Verified</div>
  <p id="msg">Verifying your browser...</p>
</div>
<script>
(function(){
  var ts  = %d;
  var tok = "%s";
  var ret = "%s";

  // Set verification cookie
  var expiry = new Date(Date.now() + %d * 1000).toUTCString();
  document.cookie = "gcs_verified=" + ts + "." + tok + "; path=/; expires=" + expiry + "; SameSite=Strict";

  // Brief pause to look human, then redirect
  setTimeout(function(){
    document.getElementById("spin").style.display = "none";
    document.getElementById("ok").style.display   = "block";
    document.getElementById("msg").textContent    = "Redirecting...";
    setTimeout(function(){ window.location.href = ret || "/"; }, 400);
  }, 600);
})();
</script>
</body>
</html>]], ts, tok, ngx.var.arg_return or "/", CHALLENGE_TTL))
end

-- ── Public: verify (POST endpoint) ───────────────────────────────────────────
function _M.verify_challenge()
    ngx.header["Content-Type"] = "application/json"
    local ip  = ngx.var.remote_addr
    local tok = ngx.var.arg_token or ""
    local ts  = tonumber(ngx.var.arg_ts or 0)
    local now = ngx.time()

    if now - ts < CHALLENGE_TTL and make_token(ip, ts) == tok then
        shared.gcs_bot_challenge:set("ok:" .. ip, true, CHALLENGE_TTL)
        ngx.say('{"status":"ok"}')
    else
        ngx.status = 403
        ngx.say('{"status":"fail"}')
    end
end

return _M
