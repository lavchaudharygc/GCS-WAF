#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GCS-WAF v2.0 — setup.sh
#  One-shot setup: checks deps, creates .env, builds containers, fetches GeoIP
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${AMBER}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║        GCS-WAF v2.0  Setup          ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Dependency checks ──────────────────────────────────────────────────────
info "Checking dependencies..."
command -v docker        >/dev/null || error "docker not found. Install from https://docs.docker.com/get-docker/"
command -v docker-compose >/dev/null || \
  (docker compose version >/dev/null 2>&1) || \
  error "docker-compose not found."
success "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

# ── 2. Create .env from example ───────────────────────────────────────────────
if [ ! -f ".env" ]; then
    info "Creating .env from .env.example..."
    cp .env.example .env

    # Generate a random WAF_SECRET
    SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 40 | head -n 1)
    sed -i "s|WAF_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_STRING_32_CHARS|WAF_SECRET=${SECRET}|" .env

    warn "Please edit .env and fill in:"
    warn "  BACKEND_HOST / BACKEND_PORT — your protected app"
    warn "  MAXMIND_LICENSE_KEY         — for GeoIP (free signup)"
    warn "  WAF_DOMAIN                  — for HTTPS/SSL"
    warn "  SLACK_WEBHOOK               — for attack alerts (optional)"
    echo ""
    read -rp "  Press Enter after editing .env (or Ctrl+C to abort)..."
fi
success ".env ready"

# ── 3. Create required local dirs ─────────────────────────────────────────────
info "Creating data directories..."
mkdir -p geoip logs/waf
success "Directories created"

# ── 4. Build containers ───────────────────────────────────────────────────────
info "Building Docker images (this may take 2-3 minutes on first run)..."
docker-compose build --parallel 2>&1 | grep -E "(Step|Successfully|Error|error)" || true
success "Images built"

# ── 5. Start core services ────────────────────────────────────────────────────
info "Starting GCS-WAF services..."
docker-compose up -d gcs-waf-redis gcs-waf-core gcs-waf-dashboard gcs-waf-scheduler

# Wait for WAF core to be healthy
info "Waiting for WAF core to start..."
for i in {1..30}; do
    if docker-compose exec -T gcs-waf-core curl -sf http://127.0.0.1/health >/dev/null 2>&1; then
        success "WAF core is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        error "WAF core did not start. Check: docker-compose logs gcs-waf-core"
    fi
    sleep 2
    printf "."
done
echo ""

# ── 6. Download GeoIP DB ──────────────────────────────────────────────────────
MAXMIND_KEY=$(grep MAXMIND_LICENSE_KEY .env | cut -d= -f2)
if [ -n "$MAXMIND_KEY" ] && [ "$MAXMIND_KEY" != "YOUR_MAXMIND_LICENSE_KEY_HERE" ]; then
    info "Downloading GeoLite2 database..."
    docker-compose exec gcs-waf-scheduler python /app/update_geoip.py
    success "GeoIP database downloaded"
else
    warn "MAXMIND_LICENSE_KEY not set — GeoIP features disabled until you add the key"
fi

# ── 7. Initial threat feed download ──────────────────────────────────────────
info "Downloading initial threat intel feeds..."
docker-compose exec gcs-waf-scheduler python /app/update_feeds.py --feed all || \
    warn "Feed download had errors (feeds will retry on next cron run)"
success "Threat feeds loaded"

# ── 8. Summary ────────────────────────────────────────────────────────────────
source .env 2>/dev/null || true
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗"
echo       "║       GCS-WAF is running!               ║"
echo       "╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  WAF Proxy:   ${BOLD}http://localhost:${WAF_HTTP_PORT:-80}${NC}"
echo -e "  Dashboard:   ${BOLD}http://localhost:${DASHBOARD_PORT:-8080}${NC}"
echo ""
echo -e "  Useful commands:"
echo -e "    ${AMBER}docker-compose logs -f gcs-waf-core${NC}       # WAF logs"
echo -e "    ${AMBER}docker-compose logs -f gcs-waf-scheduler${NC}  # scheduler logs"
echo -e "    ${AMBER}docker-compose ps${NC}                          # service status"
echo -e "    ${AMBER}docker-compose down${NC}                        # stop all"
echo ""
echo -e "  HTTPS setup (after adding WAF_DOMAIN to .env):"
echo -e "    ${AMBER}docker-compose --profile ssl up gcs-waf-certbot${NC}"
echo ""
