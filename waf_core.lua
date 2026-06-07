-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  waf_core.lua
--  Full pattern-based WAF engine: SQLi, XSS, Path Traversal, CMDi, SSRF, RFI
--  Scoring-based (threshold 50 = block), each rule adds to score
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx        = ngx
local re_find    = ngx.re.find
local shared     = ngx.shared

-- ── Attack rule sets ──────────────────────────────────────────────────────────
-- Each entry: { pattern, score, category, stat_key }
local RULES = {
    -- SQL Injection (score 50-90)
    { [[\b(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database)|alter\s+table|create\s+table|truncate\s+table)\b]], 90, "sqli", "sqli_count" },
    { [['\s*(or|and)\s+('|")?[0-9]]], 70, "sqli", "sqli_count" },
    { [[\b(exec|execute|sp_executesql|xp_cmdshell|sp_password|openrowset|bulk\s+insert)\b]], 80, "sqli", "sqli_count" },
    { [['.*--]], 60, "sqli", "sqli_count" },
    { [[\b(sleep|benchmark|waitfor\s+delay)\s*\(]], 80, "sqli", "sqli_count" },
    { [[\b(load_file|into\s+(out|dump)file)\b]], 80, "sqli", "sqli_count" },

    -- XSS (score 60-80)
    { [[<\s*script[^>]*>.*?<\s*/\s*script\s*>]], 80, "xss", "xss_count" },
    { [[<\s*script[^>]*>]], 70, "xss", "xss_count" },
    { [[javascript\s*:]], 70, "xss", "xss_count" },
    { [[on(load|error|click|mouseover|focus|blur|change|submit|keyup|keydown)\s*=]], 70, "xss", "xss_count" },
    { [[<\s*(iframe|object|embed|applet|link|meta|base)[^>]*>]], 60, "xss", "xss_count" },
    { [[expression\s*\(]], 60, "xss", "xss_count" },
    { [[vbscript\s*:]], 70, "xss", "xss_count" },
    { [[\balert\s*\(]], 50, "xss", "xss_count" },
    { [[\bdocument\.(cookie|location|write|body)\b]], 60, "xss", "xss_count" },

    -- Path Traversal (score 70)
    { [[(\.\./){2,}]], 70, "path_traversal", "path_count" },
    { [[\.\.[/\\]]], 70, "path_traversal", "path_count" },
    { [[%2e%2e[%2f%5c]]], 70, "path_traversal", "path_count" },
    { [[/etc/(passwd|shadow|hosts|group|crontab)]], 80, "path_traversal", "path_count" },
    { [[/proc/self]], 70, "path_traversal", "path_count" },
    { [[/windows/(system32|system\.ini|win\.ini)]], 80, "path_traversal", "path_count" },

    -- Command Injection (score 80)
    { [[;\s*(ls|cat|id|whoami|uname|pwd|echo|ping|wget|curl|bash|sh|python|perl|ruby)\b]], 80, "cmdi", "cmdi_count" },
    { [[\|\s*(ls|cat|id|whoami|bash|sh)\b]], 80, "cmdi", "cmdi_count" },
    { [[\$\s*\(]], 70, "cmdi", "cmdi_count" },
    { [[`[^`]+`]], 70, "cmdi", "cmdi_count" },
    { [[\b(nc|netcat|ncat)\s+-]], 80, "cmdi", "cmdi_count" },
    { [[\b(chmod|chown|rm\s+-rf|mkfifo)\b]], 80, "cmdi", "cmdi_count" },

    -- SSRF (score 70-80)
    { [[http[s]?://(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)\d+]], 80, "ssrf", "ssrf_count" },
    { [[http[s]?://localhost]], 80, "ssrf", "ssrf_count" },
    { [[169\.254\.169\.254]], 90, "ssrf", "ssrf_count" },   -- AWS metadata
    { [[file:///]], 80, "ssrf", "ssrf_count" },
    { [[dict://|gopher://|ftp://[^\s]*@]], 70, "ssrf", "ssrf_count" },
    { [[169\.254\.\d+\.\d+]], 90, "ssrf", "ssrf_count" },   -- APIPA / cloud metadata

    -- Remote File Inclusion (score 75)
    { [[https?://[^/]+/.*\.(php|asp|jsp|pl|py|sh|bash|rb)]], 75, "rfi", "rfi_count" },
    { [[(php|data|expect|zip|phar)://]], 80, "rfi", "rfi_count" },
    { [[%00$]], 70, "rfi", "rfi_count" },   -- null byte injection

    -- Malicious User Agents (score 50)
    { [[\b(sqlmap|nikto|nessus|openvas|nmap|masscan|zgrab|dirbuster|hydra|medusa|havij|acunetix|w3af|burpsuite|metasploit)\b]], 50, "scanner", "scanner_count" },
}

-- ── Allowlist for common false positives ──────────────────────────────────────
local ALLOWLIST_PATTERNS = {
    [[^/waf-api/]],
    [[^/health$]],
    [[^/waf-challenge]],
}

-- ── Decode helpers ────────────────────────────────────────────────────────────
local function url_decode(s)
    return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
              :gsub("+", " "))
end

local function normalize(s)
    if not s then return "" end
    s = url_decode(s)
    s = s:lower()
    -- collapse whitespace
    s = s:gsub("%s+", " ")
    -- remove null bytes
    s = s:gsub("%z", "")
    -- HTML entity decode basic cases
    s = s:gsub("&lt;",  "<")
    s = s:gsub("&gt;",  ">")
    s = s:gsub("&amp;", "&")
    s = s:gsub("&#(%d+);", function(n) return string.char(tonumber(n)) end)
    s = s:gsub("&#x(%x+);", function(h) return string.char(tonumber(h, 16)) end)
    return s
end

-- ── Match engine ──────────────────────────────────────────────────────────────
local function match_rules(target, context_label)
    local total_score = 0
    local matched_rule = nil
    local stats = shared.gcs_stats

    for _, rule in ipairs(RULES) do
        local pattern, score, category, stat_key = rule[1], rule[2], rule[3], rule[4]
        local m, _, err = re_find(target, pattern, "ijo")
        if m then
            total_score = total_score + score
            if not matched_rule then
                matched_rule = category .. ":" .. context_label
            end
            -- increment per-category counter
            if stat_key and stats then
                stats:incr(stat_key, 1, 0)
            end
            if total_score >= 50 then
                break  -- early exit once threshold hit
            end
        end
    end
    return total_score, matched_rule
end

-- ── Public: inspect current request ──────────────────────────────────────────
function _M.inspect()
    local uri    = ngx.var.request_uri or ""
    local method = ngx.var.request_method or "GET"
    local ua     = ngx.var.http_user_agent or ""

    -- Check allowlist first
    for _, pat in ipairs(ALLOWLIST_PATTERNS) do
        if re_find(uri, pat, "ijo") then
            return 0, nil
        end
    end

    local total = 0
    local rule  = nil

    -- Score URI
    local s, r = match_rules(normalize(uri), "uri")
    total = total + s
    if r and not rule then rule = r end
    if total >= 50 then return total, rule end

    -- Score User-Agent
    s, r = match_rules(ua:lower(), "ua")
    total = total + s
    if r and not rule then rule = r end
    if total >= 50 then return total, rule end

    -- Score query args
    local args = ngx.req.get_uri_args(50)
    for k, v in pairs(args) do
        local val = type(v) == "table" and table.concat(v, " ") or tostring(v or "")
        s, r = match_rules(normalize(val), "arg:" .. k)
        total = total + s
        if r and not rule then rule = r end
        if total >= 50 then return total, rule end

        s, r = match_rules(normalize(k), "arg_key")
        total = total + s
        if r and not rule then rule = r end
        if total >= 50 then return total, rule end
    end

    -- Score POST body
    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body and #body > 0 and #body < 65536 then
            s, r = match_rules(normalize(body), "body")
            total = total + s
            if r and not rule then rule = r end
        end
    end

    -- Score Referer / Cookie headers (lower weight)
    for _, hdr in ipairs({"http_referer", "http_cookie"}) do
        local val = ngx.var[hdr] or ""
        if #val > 0 then
            s, r = match_rules(normalize(val), hdr)
            total = total + math.floor(s * 0.5)  -- half weight for headers
            if r and not rule then rule = r end
            if total >= 50 then return total, rule end
        end
    end

    return total, rule
end

-- ── Public: simulate (for test endpoint) ─────────────────────────────────────
function _M.simulate(payload)
    local normalized = normalize(payload)
    local matches    = {}
    local total      = 0
    for _, rule in ipairs(RULES) do
        local m = re_find(normalized, rule[1], "ijo")
        if m then
            total = total + rule[2]
            table.insert(matches, { rule = rule[3], score = rule[2] })
        end
    end
    return {
        action         = total >= 50 and "block" or "allow",
        score          = total,
        rules_matched  = matches,
        payload_sample = payload:sub(1, 100)
    }
end

return _M
