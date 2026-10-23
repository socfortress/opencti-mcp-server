#!/usr/bin/env bash
# Check a built image before it is published: it runs as a non-root user, the server imports, and it
# carries no secrets, .env files, tests, vendored schemas or other repo files that don't belong in it.
#
#   scripts/check_image.sh IMAGE [PLATFORM]     e.g. scripts/check_image.sh opencti-mcp-server:check linux/amd64
#
# Used by .github/workflows/publish.yml on every platform before anything is pushed.
set -euo pipefail

image=${1:?usage: check_image.sh IMAGE [PLATFORM]}
platform=${2:-}
plat=()
[ -n "$platform" ] && plat=(--platform "$platform")
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

# 1. Non-root: the configured user, and the uid a container actually gets.
user=$(docker image inspect -f '{{.Config.User}}' "$image")
case "$user" in
  "" | root | 0 | 0:* | root:*) bad "image user is '${user:-<unset>}', expected a non-root user" ;;
esac
uid=$(docker run --rm ${plat[@]+"${plat[@]}"} --entrypoint id "$image" -u)
[ "$uid" != 0 ] || bad "container runs as uid 0"
echo "user: $user (uid $uid)"

# 2. The server's code imports with the default (empty) environment.
docker run --rm ${plat[@]+"${plat[@]}"} --entrypoint python "$image" \
  -c 'import opencti_mcp_server.server, opencti_mcp_server.__main__' || bad "the server does not import"

# 3. Files. Scanned as root so nothing is hidden by permissions; /proc, /sys and /dev are skipped.
found=$(docker run --rm ${plat[@]+"${plat[@]}"} --user 0 --entrypoint sh "$image" -c '
  set -u
  prune="-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o"
  # .env files and private keys anywhere.
  find / $prune \( -name ".env" -o -name ".env.*" -o -name "*.key" -o -name "id_rsa*" -o -name "id_ed25519*" \
    -o -name "*.p12" -o -name "*.pfx" \) -print
  find / $prune -type f \( -name "*.pem" -o -name "*.crt" \) -size -64k -print 2>/dev/null \
    | xargs -r grep -l "PRIVATE KEY" 2>/dev/null
  # Only the virtualenv under /app; no repo files (tests, scripts, docs, .git, uv.lock ...).
  find /app -mindepth 1 -maxdepth 1 ! -name .venv -print
  # The installed package holds its modules only.
  pkg=$(python -c "import os, opencti_mcp_server; print(os.path.dirname(opencti_mcp_server.__file__))")
  find "$pkg" -type f ! -name "*.py" ! -name "*.pyc" -print
  # Tests, their fakes and the vendored OpenCTI schemas stay in the repo.
  find / $prune \( -name "test_unit.py" -o -name "test_contract.py" -o -name "test_live.py" -o -name "fakes.py" \
    -o -name "000-main.graphql" -o -name "check_image.sh" \) -print
  # Home directories: nothing beyond the skeleton files (and the wget HSTS cache from the base image).
  find /home /root -type f ! -name ".bashrc" ! -name ".profile" ! -name ".bash_logout" \
    ! -path /root/.wget-hsts -print 2>/dev/null
' | sort -u)
if [ -n "$found" ]; then
  bad "files that don't belong in the image:"
  printf '%s\n' "$found" | sed 's/^/  /' >&2
fi

# 4. No secrets in the image configuration.
envs=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$image")
if printf '%s\n' "$envs" | grep -Eiq '^(OPENCTI_TOKEN|OPENCTI_URL|MCP_AUTH_TOKEN)=|(PASSWORD|TOKEN|SECRET)=.'; then
  bad "secret-looking environment in the image config"
fi

if [ "$fail" = 0 ]; then
  echo "ok: $image${platform:+ ($platform)}"
fi
exit "$fail"
