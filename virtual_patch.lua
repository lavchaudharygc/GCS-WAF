-- ─────────────────────────────────────────────────────────────────────────────
--  GCS-WAF  virtual_patch.lua
--  Virtual Patching: create on-the-fly WAF rules without restarting nginx.
--  Rules are stored in shared dict + Redis and evaluated on every request.
-- ─────────────────────────────────────────────────────────────────────────────

local _M = { _VERSION = "2.0" }

local ngx    = ngx
local shared = ngx.shared
local cjson  = require("cjson")
local re_find = ngx.re.find

-- ── patch rule format ─────────────────────────────────────────────────────────
-- { id, pattern, target, description, created_at, hits, enabled }
-- target: "uri" | "body" | "args" | "headers" | "any"

local PATCH_TTL = 0  -- 0 = permanent (until explicitly removed)

-- ── Helpers ───────────────────────────────────────────────────────────────────
local function load_patches()
    local vp   = shared.gcs_virtual_patch
    local data = vp:get("patches")
    if not data then return {} end
    local ok, patches = pcall(cjson.decode, data)
    return ok and patches or {}
end

local function save_patches(patches)
    local vp = shared.gcs_virtual_patch
    vp:set("patches", cjson.encode(patches))
end

-- ── Public: check current request against all virtual patches ────────────────
function _M.check()
    local patches = load_patches()
    if #patches == 0 then return false, nil end

    local uri     = (ngx.var.request_uri or ""):lower()
    local body    = ""
    local method  = ngx.var.request_method or "GET"

    if method == "POST" or method == "PUT" then
        ngx.req.read_body()
        body = (ngx.req.get_body_data() or ""):lower()
    end

    local args_str = ""
    for k, v in pairs(ngx.req.get_uri_args(20)) do
        local val = type(v) == "table" and table.concat(v, " ") or tostring(v)
        args_str = args_str .. k .. "=" .. val .. "&"
    end

    for _, patch in ipairs(patches) do
        if patch.enabled ~= false then
            local targets = {}
            if     patch.target == "uri"     then targets = { uri }
            elseif patch.target == "body"    then targets = { body }
            elseif patch.target == "args"    then targets = { args_str }
            else   targets = { uri, body, args_str }
            end

            for _, t in ipairs(targets) do
                local m, _, err = re_find(t, patch.pattern, "ijo")
                if m then
                    -- increment hit count async
                    local patch_id = patch.id
                    ngx.timer.at(0, function()
                        local ps = load_patches()
                        for _, p in ipairs(ps) do
                            if p.id == patch_id then
                                p.hits = (p.hits or 0) + 1
                                break
                            end
                        end
                        save_patches(ps)
                    end)
                    return true, patch.id
                end
            end
        end
    end
    return false, nil
end

-- ── Public: REST API handler ──────────────────────────────────────────────────
function _M.handle_api()
    local method = ngx.var.request_method
    ngx.header["Content-Type"] = "application/json"

    if method == "GET" then
        -- List all patches
        local patches = load_patches()
        ngx.say(cjson.encode({ patches = patches, count = #patches }))

    elseif method == "POST" then
        -- Create new patch
        ngx.req.read_body()
        local body = ngx.req.get_body_data() or "{}"
        local ok, data = pcall(cjson.decode, body)
        if not ok or not data.pattern then
            ngx.status = 400
            ngx.say('{"error":"pattern required"}')
            return
        end
        -- Validate regex
        local test_ok, test_err = re_find("test", data.pattern, "ijo")
        if test_ok == nil and test_err then
            ngx.status = 400
            ngx.say(cjson.encode({ error = "invalid regex: " .. tostring(test_err) }))
            return
        end

        local patches = load_patches()
        local new_patch = {
            id          = "vp_" .. ngx.time() .. "_" .. math.random(1000),
            pattern     = data.pattern,
            target      = data.target or "any",
            description = data.description or "Virtual patch",
            created_at  = ngx.time(),
            hits        = 0,
            enabled     = true,
        }
        table.insert(patches, new_patch)
        save_patches(patches)
        ngx.status = 201
        ngx.say(cjson.encode({ status = "created", patch = new_patch }))

    elseif method == "DELETE" then
        -- Delete patch by id
        local patch_id = ngx.var.arg_id
        if not patch_id then
            ngx.status = 400
            ngx.say('{"error":"id required"}')
            return
        end
        local patches = load_patches()
        local new_patches = {}
        local deleted = false
        for _, p in ipairs(patches) do
            if p.id == patch_id then
                deleted = true
            else
                table.insert(new_patches, p)
            end
        end
        save_patches(new_patches)
        if deleted then
            ngx.say('{"status":"deleted"}')
        else
            ngx.status = 404
            ngx.say('{"error":"not found"}')
        end

    elseif method == "PUT" then
        -- Toggle patch enabled/disabled
        ngx.req.read_body()
        local body = ngx.req.get_body_data() or "{}"
        local ok, data = pcall(cjson.decode, body)
        if not ok or not data.id then
            ngx.status = 400
            ngx.say('{"error":"id required"}')
            return
        end
        local patches = load_patches()
        for _, p in ipairs(patches) do
            if p.id == data.id then
                p.enabled = data.enabled ~= false
                break
            end
        end
        save_patches(patches)
        ngx.say('{"status":"updated"}')

    else
        ngx.status = 405
        ngx.say('{"error":"method not allowed"}')
    end
end

return _M
