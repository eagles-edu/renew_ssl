#!/usr/bin/env bash
# /usr/local/sbin/acme_dns_manual_nginx_swap.sh
# Purpose: Safely swap Nginx config, re-issue/renew ECC cert via acme.sh manual DNS, verify public+authoritative TXT, restore prod config, install cert.
# Notes:
# - Designed to be run as root (sudo -i).
# - Uses a lock + trap-based rollback to avoid leaving nginx in a broken state.
# - Emits informative error/warning messages with concrete next steps (no vague "internal error").

set -euo pipefail

# ---------- Config (edit only if your paths differ) ----------
ACME="/root/.acme.sh/acme.sh"
NGINX_ENABLED="/etc/nginx/sites-enabled"
SSL_REPO="/etc/nginx/sites-available/ssl_conf_repo"
TEMP_DIR="/etc/nginx/temp_production_symlink"
LOCK_FILE="/run/lock/acme-dns-manual-nginx-swap.lock"
LOG_DIR="/var/log"

# Public resolvers for propagation checks
PUBLIC_RESOLVERS=( "1.1.1.1" "8.8.8.8" "9.9.9.9" )

# ---------- State (used for rollback) ----------
DOMAIN=""
WWW=""
LOG_FILE=""
PROD_ENABLED_PATH=""
PROD_MOVED_PATH=""
STAGE_LINK_PATH=""
STAGE_CONF_PATH=""
ROLLBACK_NEEDED="no"
ECC_DIR=""
ECC_BACKUP=""
ECC_REMOVED="no"

# ---------- Messaging helpers ----------
ts() { date +"%F %T %z"; }
info() { echo "INFO  [$(ts)] $*"; }
warn() { echo "WARN  [$(ts)] $*"; }
err()  { echo "ERROR [$(ts)] $*"; }
die()  { err "$*"; exit 1; }

# Print command then run it (stdout preserved via global logging tee)
run() {
  info "RUN: $*"
  "$@"
}

pause_enter() {
  echo
  read -r -p "ACTION: $*  (press Enter to continue) " _ || true
}

ask_yes_no() {
  local prompt="$1" ans
  while true; do
    read -r -p "PROMPT: ${prompt} [y/n]: " ans || true
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) warn "Please answer 'y' or 'n'." ;;
    esac
  done
}

# ---------- Lock ----------
acquire_lock() {
  mkdir -p "$(dirname "$LOCK_FILE")" || true
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    die "Another instance is already running (lock: $LOCK_FILE). If you're sure it's stale, remove it and retry."
  fi
}

# ---------- Rollback ----------
rollback() {
  local why="${1:-unspecified reason}"
  warn "Rollback initiated: ${why}"
  set +e

  # Restore Nginx prod entry if we swapped it
  if [ "$ROLLBACK_NEEDED" = "yes" ]; then
    if [ -n "$STAGE_LINK_PATH" ] && [ -L "$STAGE_LINK_PATH" ]; then
      info "Removing staged symlink: $STAGE_LINK_PATH"
      rm -f "$STAGE_LINK_PATH"
    fi

    if [ -n "$PROD_MOVED_PATH" ] && [ -e "$PROD_MOVED_PATH" ]; then
      info "Restoring production entry to: $PROD_ENABLED_PATH"
      mv -f "$PROD_MOVED_PATH" "$PROD_ENABLED_PATH"
    fi

    # Restore ECC backup if we removed the live dir earlier
    if [ "$ECC_REMOVED" = "yes" ] && [ -n "$ECC_BACKUP" ] && [ -d "$ECC_BACKUP" ]; then
      info "Restoring ECC backup from: $ECC_BACKUP -> $ECC_DIR"
      rm -rf "$ECC_DIR"
      cp -a "$ECC_BACKUP" "$ECC_DIR"
    fi

    # Validate & reload only if nginx exists
    if command -v nginx >/dev/null 2>&1; then
      info "Validating nginx config after rollback (nginx -t)..."
      if nginx -t; then
        systemctl reload nginx || warn "Nginx reload failed after rollback. Run: nginx -t ; systemctl status nginx"
      else
        warn "nginx -t failed after rollback. Run: nginx -t ; systemctl status nginx"
      fi
    fi
  fi

  warn "Rollback complete. Exiting."
  exit 1
}

on_exit() {
  # Do not auto-rollback on normal exit; rollback is explicit via traps/errors.
  :
}

trap 'rollback "received interrupt/signal"' INT TERM
trap 'rollback "command failed at line $LINENO"' ERR
trap 'on_exit' EXIT

# ---------- Preflight ----------
require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "This script must be run as root (use: sudo -i)."
  fi
}

require_bin() {
  local b="$1" hint="$2"
  command -v "$b" >/dev/null 2>&1 || die "Required binary missing: '$b'. ${hint}"
}

require_file_exec() {
  local f="$1"
  [ -x "$f" ] || die "Required executable not found or not executable: $f"
}

# ---------- Domain validation ----------
validate_domain() {
  local d="$1"
  # Accept letters/digits/dots/hyphens; reject empty, spaces, slashes, leading dot, trailing dot handled separately.
  if [ -z "$d" ]; then
    die "Domain is empty. Provide a fully-qualified domain like: example.com"
  fi
  if [[ "$d" =~ [[:space:]/\\] ]]; then
    die "Domain '$d' contains spaces or slashes. Provide a plain FQDN only."
  fi
  d="${d%.}" # strip trailing dot (harmless)
  if ! [[ "$d" =~ ^[A-Za-z0-9.-]+$ ]]; then
    die "Domain '$d' contains invalid characters. Allowed: A-Z a-z 0-9 dot (.) hyphen (-)."
  fi
  if [[ "$d" == .* ]] || [[ "$d" == *..* ]] || [[ "$d" == *.-* ]] || [[ "$d" == *-.* ]]; then
    warn "Domain '$d' looks unusual (leading dot/double dot/dangling hyphen patterns). Double-check spelling."
  fi
  echo "$d"
}

# ---------- Nginx prod entry detection ----------
detect_prod_enabled_entry() {
  local d="$1"
  local c1="${NGINX_ENABLED}/${d}.conf"
  local c2="${NGINX_ENABLED}/${d}"
  local found=""

  if [ -e "$c1" ]; then
    found="$c1"
  elif [ -e "$c2" ]; then
    found="$c2"
  else
    # Try strict match in directory listing (no globbing in filesystem ops)
    local matches
    matches="$(ls -1 "$NGINX_ENABLED" 2>/dev/null | awk -v d="$d" '$0==d || $0==(d".conf") {print $0}' || true)"
    if [ -n "$matches" ]; then
      found="${NGINX_ENABLED}/$(echo "$matches" | head -n 1)"
      warn "Multiple candidates may exist; selecting first match: $found"
    fi
  fi

  [ -n "$found" ] || die "Could not find production enabled site entry for '$d' in $NGINX_ENABLED.
Expected one of:
  - ${NGINX_ENABLED}/${d}.conf
  - ${NGINX_ENABLED}/${d}
Fix: create/enable the site entry or adjust detection logic for your naming."

  echo "$found"
}

detect_stage_conf() {
  local d="$1"
  local p1="${SSL_REPO}/${d}_ssl.conf"
  local p2="${SSL_REPO}/${d}_ssl"
  local found=""

  if [ -f "$p1" ]; then
    found="$p1"
  elif [ -f "$p2" ]; then
    found="$p2"
  fi

  [ -n "$found" ] || die "Staged SSL config not found for '$d'.
Expected: ${SSL_REPO}/${d}_ssl.conf
Fix: create that file or adjust SSL_REPO path."

  echo "$found"
}

# ---------- DNS helpers (public + authoritative) ----------
dig_txt_short() {
  local fqdn="$1" server="$2"
  # Normalize quotes; TXT can return multiple quoted segments; join lines for match checks.
  dig +short TXT "$fqdn" @"$server" 2>/dev/null | tr -d '"' | sed '/^\s*$/d' || true
}

detect_zone_apex() {
  local name="$1" soa owner
  while :; do
    soa="$(dig +noall +authority SOA "$name" 2>/dev/null | tail -n 1 || true)"
    if [ -n "$soa" ]; then
      owner="$(awk '{print $1}' <<<"$soa")"
      echo "${owner%.}"
      return 0
    fi

    soa="$(dig +noall +answer SOA "$name" 2>/dev/null | tail -n 1 || true)"
    if [ -n "$soa" ]; then
      owner="$(awk '{print $1}' <<<"$soa")"
      echo "${owner%.}"
      return 0
    fi

    if [[ "$name" != *.* ]]; then
      return 1
    fi
    name="${name#*.}"
  done
}

get_auth_ns_list() {
  local zone="$1"
  dig +short NS "$zone" 2>/dev/null | sed 's/\.$//' | sed '/^\s*$/d' || true
}

resolve_ns_ips() {
  local ns="$1"
  local ips4 ips6
  ips4="$(dig +short A "$ns" 2>/dev/null | sed '/^\s*$/d' || true)"
  ips6="$(dig +short AAAA "$ns" 2>/dev/null | sed '/^\s*$/d' || true)"
  { [ -n "$ips4" ] && echo "$ips4"; [ -n "$ips6" ] && echo "$ips6"; } | sed '/^\s*$/d' || true
}

dig_txt_authoritative_verbose() {
  local fqdn="$1" ip="$2"
  # Show header status + answer section only
  dig +time=2 +tries=1 +norecurse +noall +comments +answer TXT "$fqdn" @"$ip" 2>/dev/null || true
}

# Returns 0 if expected present (or any TXT present if expected empty), else 1.
check_public_resolvers() {
  local fqdn="$1" expected="${2:-}"
  local ok_any="no"
  local r out

  echo
  info "Public resolver check for TXT: $fqdn"
  for r in "${PUBLIC_RESOLVERS[@]}"; do
    out="$(dig_txt_short "$fqdn" "$r")"
    if [ -z "$out" ]; then
      warn "Resolver @$r: no TXT answer yet (could be propagation delay or record missing)."
      continue
    fi

    info "Resolver @$r returned TXT:"
    while IFS= read -r line; do
      printf '  - %s\n' "$line"
    done <<<"$out"

    if [ -n "$expected" ]; then
      if echo "$out" | grep -Fq "$expected"; then
        info "Resolver @$r: MATCH (expected token present)."
        ok_any="yes"
      else
        warn "Resolver @$r: MISMATCH (token differs). Expected: '$expected'. Check you pasted the exact value from acme.sh (no extra quotes/spaces)."
      fi
    else
      ok_any="yes"
    fi
  done

  [ "$ok_any" = "yes" ]
}

# Returns 0 if any authoritative NS IP shows expected present (or any TXT present if expected empty), else 1.
check_authoritative_ns() {
  local fqdn="$1" expected="${2:-}"
  local zone ns_list ns ip out header answers ok_any="no"

  echo
  info "Authoritative nameserver check for TXT: $fqdn"

  zone="$(detect_zone_apex "$DOMAIN" || true)"
  if [ -z "$zone" ]; then
    warn "Could not detect zone apex via SOA for '$DOMAIN'. Skipping authoritative NS check (will rely on public resolvers)."
    return 1
  fi
  info "Detected zone apex (SOA owner): $zone"

  ns_list="$(get_auth_ns_list "$zone")"
  if [ -z "$ns_list" ]; then
    warn "No NS records returned for zone '$zone'. Skipping authoritative NS check (will rely on public resolvers)."
    return 1
  fi
  info "Authoritative NS for '$zone':"
  while IFS= read -r line; do
    printf '  - %s\n' "$line"
  done <<<"$ns_list"

  while read -r ns; do
    [ -n "$ns" ] || continue
    while read -r ip; do
      [ -n "$ip" ] || continue

      out="$(dig_txt_authoritative_verbose "$fqdn" "$ip")"
      header="$(grep -m1 '^;; ->>HEADER<<-' <<<"$out" || true)"
      answers="$(grep -v '^;;' <<<"$out" | sed '/^\s*$/d' || true)"

      if [ -z "$header" ]; then
        warn "Authoritative '$ns' ($ip): no DNS header returned. Possible firewall/UDP issues. Try: dig +tcp TXT $fqdn @$ip"
        continue
      fi

      if grep -q 'status: SERVFAIL' <<<"$header"; then
        warn "Authoritative '$ns' ($ip): SERVFAIL for '$fqdn' (transient NS failure or upstream issue)."
        continue
      fi
      if grep -q 'status: REFUSED' <<<"$header"; then
        warn "Authoritative '$ns' ($ip): REFUSED for '$fqdn' (policy restriction). Try TCP: dig +tcp TXT $fqdn @$ip"
        continue
      fi
      if grep -q 'status: NXDOMAIN' <<<"$header"; then
        warn "Authoritative '$ns' ($ip): NXDOMAIN for '$fqdn'. Likely record name wrong or created in the wrong zone/account."
        continue
      fi

      if [ -z "$answers" ]; then
        warn "Authoritative '$ns' ($ip): NOERROR but no TXT answers yet (record not present on this NS or not propagated between NS)."
        continue
      fi

      info "Authoritative '$ns' ($ip) answers:"
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done <<<"$answers"

      if [ -n "$expected" ]; then
        if echo "$answers" | grep -Fq "\"$expected\"" || echo "$answers" | grep -Fq "$expected"; then
          info "Authoritative '$ns' ($ip): MATCH (expected token present)."
          ok_any="yes"
        else
          warn "Authoritative '$ns' ($ip): MISMATCH. Expected: '$expected'. Verify TXT value exactly (no extra quoting/spaces)."
        fi
      else
        ok_any="yes"
      fi
    done < <(resolve_ns_ips "$ns" || true)
  done <<<"$ns_list"

  [ "$ok_any" = "yes" ]
}

# ---------- acme.sh output parsing (best-effort; prompts if parsing fails) ----------
parse_expected_txt_from_issue_output() {
  local fqdn="$1" issue_out="$2"
  # acme.sh manual DNS typically prints blocks:
  #   Domain: '_acme-challenge.example.com'
  #   TXT value: 'TOKEN'
  awk -v fqdn="$fqdn" '
    BEGIN{IGNORECASE=1; inblk=0}
    $0 ~ /Domain:/ && $0 ~ fqdn {inblk=1; next}
    inblk && $0 ~ /TXT value:/ {
      sub(/.*TXT value:[[:space:]]*/, "", $0)
      gsub(/^[ "\x27]+|[ "\x27]+$/, "", $0)   # trim spaces/quotes (incl apostrophe 0x27)
      print $0
      exit
    }
  ' "$issue_out" | head -n 1
}

# ---------- Main ----------
main() {
  require_root
  acquire_lock

  require_bin flock "Install util-linux (usually already present)."
  require_bin nginx "Install nginx or adjust script to your web server."
  require_bin systemctl "This script expects systemd."
  require_bin dig "Install 'dnsutils' (Ubuntu): apt-get install -y dnsutils"
  require_bin openssl "Install openssl for final verification (optional but recommended)."
  require_file_exec "$ACME"

  mkdir -p "$TEMP_DIR" "$LOG_DIR"

  echo
  read -r -p "INPUT: enter domain name (e.g., example.com): " DOMAIN_RAW || true
  DOMAIN="$(validate_domain "${DOMAIN_RAW:-}")"
  WWW="www.${DOMAIN}"
  ECC_DIR="/root/.acme.sh/${DOMAIN}_ecc"

  LOG_FILE="${LOG_DIR}/acme-dns-manual-${DOMAIN}-$(date +%F-%H%M%S).log"
  # Start logging AFTER we know the domain for per-domain log filenames.
  exec > >(tee -a "$LOG_FILE") 2>&1
  info "Logging to: $LOG_FILE"

  info "stdout - verify default CA is Let's Encrypt"
  run "$ACME" --set-default-ca --server letsencrypt

  info "stdout - acme.sh --list"
  run "$ACME" --list

  info "stdout - acme.sh --info (best-effort; may be empty if not issued yet)"
  run "$ACME" --info -d "$DOMAIN" --ecc || warn "No existing ECC info for $DOMAIN (this is ok if you're re-issuing)."
  if [ "$WWW" != "$DOMAIN" ]; then
    info "SAN note: acme.sh stores the SAN entry for $WWW inside the same config dir as $DOMAIN (usually ${ECC_DIR}/${DOMAIN}.conf). A separate www.* conf directory is not created."
  fi

  # Detect production enabled entry + staged SSL conf
  PROD_ENABLED_PATH="$(detect_prod_enabled_entry "$DOMAIN")"
  STAGE_CONF_PATH="$(detect_stage_conf "$DOMAIN")"
  STAGE_LINK_PATH="${NGINX_ENABLED}/$(basename "$PROD_ENABLED_PATH")"

  info "Detected production enabled entry: $PROD_ENABLED_PATH"
  info "Staged SSL conf to enable: $STAGE_CONF_PATH"
  info "Staged symlink path will be: $STAGE_LINK_PATH"

  # Swap nginx: move prod -> temp, enable stage
  info "stdout - move production entry to temp: $TEMP_DIR"
  local moved_target="${TEMP_DIR}/$(basename "$PROD_ENABLED_PATH")"
  if [ -e "$moved_target" ]; then
    moved_target="${moved_target}.bak.$(date +%F-%H%M%S)"
    warn "Temp target already existed; using unique name: $moved_target"
  fi
  run mv -f "$PROD_ENABLED_PATH" "$moved_target"
  PROD_MOVED_PATH="$moved_target"
  ROLLBACK_NEEDED="yes"

  info "stdout - create symlink for staged ssl conf in sites-enabled"
  run ln -sfn "$STAGE_CONF_PATH" "$STAGE_LINK_PATH"

  info "stdout - nginx status + test + reload"
  run systemctl status nginx --no-pager || true
  run nginx -t
  run systemctl reload nginx
  run systemctl status nginx --no-pager || true

  echo
  info "Checkpoint: Nginx staging swap is active."
  if ! ask_yes_no "Report SUCCESS so far and proceed to acme issue/renew for '$DOMAIN' and '$WWW'?"; then
    rollback "user chose not to proceed at checkpoint"
  fi

  pause_enter "Prepare to add TWO DNS TXT records in your DNS provider when prompted by acme.sh. Ensure you can edit the zone now."

  # Backup ECC entry
  if [ -d "$ECC_DIR" ]; then
    ECC_BACKUP="${ECC_DIR}.bak.$(date +%F-%H%M%S)"
    info "stdout - backup ECC cert entry"
    run cp -a "$ECC_DIR" "$ECC_BACKUP"
  else
    warn "ECC directory not found at $ECC_DIR. This is ok if you're issuing fresh; backup skipped."
  fi

  # Remove ECC entry cleanly
  info "stdout - remove ECC cert entry cleanly (acme.sh --remove), then filesystem cleanup"
  run "$ACME" --remove -d "$DOMAIN" --ecc || warn "acme.sh --remove reported an issue (often ok if entry already absent)."
  run rm -rf "$ECC_DIR" || warn "Failed to remove $ECC_DIR (permissions/lock). Remove manually if needed."
  ECC_REMOVED="yes"

  # Issue (manual DNS) - capture output for TXT parsing
  local issue_out
  issue_out="$(mktemp)"
  info "stdout - run acme.sh --issue (manual DNS). This will print required TXT records."
  set +e
  "$ACME" --issue \
    -d "$DOMAIN" -d "$WWW" \
    --keylength ec-256 \
    --dns \
    --yes-I-know-dns-manual-mode-enough-go-ahead-please \
    --dnssleep 120 \
    --debug 2 2>&1 | tee "$issue_out"
  local issue_rc="${PIPESTATUS[0]}"
  set -e
  if [ "$issue_rc" -ne 0 ]; then
    if grep -qi "DNS record not yet added" "$issue_out" || grep -qi "Please add the TXT records" "$issue_out"; then
      warn "acme.sh --issue exited $issue_rc because TXT records are not yet added (manual DNS). Continuing to propagation checks with the printed tokens."
    else
      err "acme.sh --issue failed (exit $issue_rc). Inspect output above and log: $LOG_FILE"
      err "Common fixes: wrong DNS provider zone, blocked outbound DNS, or acme.sh account/CA issues."
      rollback "acme.sh --issue failed"
    fi
  fi

  # Parse expected TXT values (best-effort)
  local expected_apex expected_www
  expected_apex="$(parse_expected_txt_from_issue_output "_acme-challenge.${DOMAIN}" "$issue_out" || true)"
  expected_www="$(parse_expected_txt_from_issue_output "_acme-challenge.${WWW}" "$issue_out" || true)"

  echo
  if [ -n "$expected_apex" ] && [ -n "$expected_www" ]; then
    info "Parsed expected TXT values from acme.sh output:"
    info "  _acme-challenge.${DOMAIN}      TXT: $expected_apex"
    info "  _acme-challenge.${WWW}         TXT: $expected_www"
  else
    warn "Could not reliably parse both TXT values from acme.sh output."
    warn "This can happen if acme.sh output format differs or the provider prints multi-line tokens."
    echo
    read -r -p "INPUT: Paste TXT value for _acme-challenge.${DOMAIN} (no surrounding quotes): " expected_apex || true
    read -r -p "INPUT: Paste TXT value for _acme-challenge.${WWW} (no surrounding quotes): " expected_www || true
    expected_apex="${expected_apex//\"/}"
    expected_www="${expected_www//\"/}"
    [ -n "$expected_apex" ] || die "Missing expected TXT for _acme-challenge.${DOMAIN}. Cannot safely verify propagation."
    [ -n "$expected_www" ]  || die "Missing expected TXT for _acme-challenge.${WWW}. Cannot safely verify propagation."
  fi

  pause_enter "Proceed with BOTH DNS TXT record additions now. When completed, press Enter here."

  # Propagation loop
  while true; do
    echo
    info "DNS propagation verification (public resolvers + authoritative NS)"

    local ok_pub_apex="no" ok_pub_www="no" ok_auth_apex="no" ok_auth_www="no"

    if check_public_resolvers "_acme-challenge.${DOMAIN}" "$expected_apex"; then ok_pub_apex="yes"; fi
    if check_public_resolvers "_acme-challenge.${WWW}"    "$expected_www";  then ok_pub_www="yes";  fi

    if check_authoritative_ns "_acme-challenge.${DOMAIN}" "$expected_apex"; then ok_auth_apex="yes"; fi
    if check_authoritative_ns "_acme-challenge.${WWW}"    "$expected_www";  then ok_auth_www="yes";  fi

    echo
    info "DNS check summary:"
    info "  Public resolvers: apex=$ok_pub_apex  www=$ok_pub_www"
    info "  Authoritative NS: apex=$ok_auth_apex www=$ok_auth_www"

    if [ "$ok_pub_apex" = "yes" ] && [ "$ok_pub_www" = "yes" ] && [ "$ok_auth_apex" = "yes" ] && [ "$ok_auth_www" = "yes" ]; then
      info "DNS appears propagated (public + authoritative checks passed)."
      break
    fi

    warn "DNS not fully propagated yet."
    warn "Guidance: wait 2–10 minutes, ensure you created records in the correct DNS zone, and confirm no old TXT records conflict."
    echo
    read -r -p "ACTION: press 't' to try again, or 'q' to restore nginx config and quit: " choice || true
    case "${choice,,}" in
      t) continue ;;
      q) rollback "user quit during DNS propagation checks" ;;
      *) warn "Unrecognized choice '$choice'. Type 't' to retry or 'q' to quit." ;;
    esac
  done

  echo
  if ! ask_yes_no "Ready to run acme.sh --renew now (manual DNS, ECC) for '$DOMAIN' and '$WWW'?"; then
    rollback "user declined renew step"
  fi

  # Renew
  info "stdout - run acme.sh --renew (manual DNS, ECC)"
  set +e
  "$ACME" --renew \
    -d "$DOMAIN" -d "$WWW" \
    --ecc \
    --dns \
    --yes-I-know-dns-manual-mode-enough-go-ahead-please \
    --debug 2
  local renew_rc="$?"
  set -e
  if [ "$renew_rc" -ne 0 ]; then
    err "acme.sh --renew failed (exit $renew_rc)."
    err "Common causes: TXT mismatch, TXT not reachable by CA yet, multiple conflicting TXT records, or timing."
    if ask_yes_no "Retry renew now?"; then
      info "Retrying renew..."
      run "$ACME" --renew -d "$DOMAIN" -d "$WWW" --ecc --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please --debug 2
    else
      rollback "renew failed and user chose not to retry"
    fi
  fi

  info "stdout - acme.sh --info and --list after renew"
  run "$ACME" --info -d "$DOMAIN" --ecc
  run "$ACME" --info -d "$WWW"    --ecc
  run "$ACME" --list

  echo
  if ! ask_yes_no "Proceed to restore production nginx config and install the cert paths?"; then
    rollback "user chose not to restore/install after successful renew"
  fi

  # Restore prod nginx config (remove staged symlink and move back prod)
  info "stdout - delete staged symlink in sites-enabled"
  if [ -L "$STAGE_LINK_PATH" ]; then
    run rm -f "$STAGE_LINK_PATH"
  else
    warn "Expected staged symlink not found at $STAGE_LINK_PATH (it may have been modified). Continuing."
  fi

  info "stdout - restore production entry back into sites-enabled"
  if [ -e "$PROD_MOVED_PATH" ]; then
    run mv -f "$PROD_MOVED_PATH" "$PROD_ENABLED_PATH"
  else
    die "Production entry missing in temp location ($PROD_MOVED_PATH). Cannot safely restore. Restore manually and rerun nginx -t."
  fi

  # Detect ssl_certificate paths from production config (best-effort)
  local prod_real prod_conf ssl_cert ssl_key
  prod_real="$(readlink -f "$PROD_ENABLED_PATH" 2>/dev/null || true)"
  prod_conf="${prod_real:-$PROD_ENABLED_PATH}"

  ssl_cert="$(awk '
    $1=="ssl_certificate" {
      gsub(/;$/, "", $2); print $2; exit
    }' "$prod_conf" 2>/dev/null || true)"

  ssl_key="$(awk '
    $1=="ssl_certificate_key" {
      gsub(/;$/, "", $2); print $2; exit
    }' "$prod_conf" 2>/dev/null || true)"

  if [ -n "$ssl_cert" ] && [ -n "$ssl_key" ]; then
    info "Detected ssl_certificate paths from production config:"
    info "  ssl_certificate:     $ssl_cert"
    info "  ssl_certificate_key: $ssl_key"
    mkdir -p "$(dirname "$ssl_cert")" "$(dirname "$ssl_key")" || true

    info "stdout - acme.sh --install-cert using detected nginx paths (best practice)"
    run "$ACME" --install-cert -d "$DOMAIN" --ecc \
      --key-file       "$ssl_key" \
      --fullchain-file "$ssl_cert" \
      --reloadcmd      "systemctl reload nginx"
  else
    warn "Could not detect ssl_certificate / ssl_certificate_key in production config: $prod_conf"
    warn "Fallback: installing cert to /etc/ssl/acme/${DOMAIN}/ (you must ensure nginx references these paths or already references acme.sh live paths)."

    local fallback_dir="/etc/ssl/acme/${DOMAIN}"
    mkdir -p "$fallback_dir"
    local fb_key="${fallback_dir}/privkey.ec-256.pem"
    local fb_chain="${fallback_dir}/fullchain.ec-256.pem"

    run "$ACME" --install-cert -d "$DOMAIN" --ecc \
      --key-file       "$fb_key" \
      --fullchain-file "$fb_chain" \
      --reloadcmd      "systemctl reload nginx"
  fi

  info "stdout - nginx status + test + reload"
  run systemctl status nginx --no-pager || true
  run nginx -t
  run systemctl reload nginx
  run systemctl status nginx --no-pager || true

  # Final verification (localhost)
  echo
  info "Final verify: show served certificate dates via openssl (localhost:443)"
  set +e
  openssl s_client -servername "$DOMAIN" -connect 127.0.0.1:443 </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates
  local ossl_rc="$?"
  set -e
  if [ "$ossl_rc" -ne 0 ]; then
    warn "OpenSSL verification failed. Nginx may not be listening on 443 locally, or firewall/port mapping differs. Validate externally with: openssl s_client -servername $DOMAIN -connect $DOMAIN:443"
  fi

  info "SUCCESS: Completed DNS-manual ECC issue/renew with staging nginx swap and restored production config."
  info "Backup directories (if created) remain under /root/.acme.sh/${DOMAIN}_ecc.bak.*"
  info "Log file: $LOG_FILE"
}

main "$@"
