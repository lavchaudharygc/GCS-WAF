FROM openresty/openresty:alpine

# ── system deps ──────────────────────────────────────────────────────────────
RUN apk add --no-cache \
    libmaxminddb-dev \
    libmaxminddb \
    curl \
    sqlite \
    sqlite-dev \
    lua5.1-dev \
    luarocks5.1 \
    tzdata \
    bash \
    tini

# ── Lua deps via OPM / LuaRocks ──────────────────────────────────────────────
# lua-resty-redis  → already bundled with OpenResty
# lua-resty-string → already bundled
# lua-resty-lock   → already bundled
# We only need the mmdb reader for GeoLite2
RUN opm get leafo/lua-geoip 2>/dev/null || true

# Install luarocks packages
RUN luarocks-5.1 install lua-cjson 2>/dev/null || true

# ── pre-create all directories WAF needs ─────────────────────────────────────
RUN mkdir -p \
    /etc/nginx/waf \
    /etc/nginx/waf/rules \
    /etc/nginx/geoip \
    /var/log/gcs-waf \
    /var/cache/gcs-waf \
    /etc/nginx/conf.d

# ── copy static rule files ────────────────────────────────────────────────────
COPY rules/ /etc/nginx/waf/rules/
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf
COPY *.lua /etc/nginx/waf/

# ── healthcheck so Docker knows if core is alive ─────────────────────────────
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://127.0.0.1/health || exit 1

# use tini as PID 1 to reap zombie processes correctly
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
