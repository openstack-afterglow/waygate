#!/bin/bash
set -euo pipefail

usage() {
    echo 'Usage: scripts/upload_gateway_image.sh <path.qcow2> [--name NAME] [--visibility public|community] [--project-scoped]'
    echo 'Uses standard OpenStack CLI authentication. --project-scoped requires an effective project-scoped token; it does not rescope credentials.'
}
if [ "${1:-}" = --help ] || [ "${1:-}" = -h ]; then usage; exit 0; fi
[ "$#" -ge 1 ] || { usage >&2; exit 2; }
QCOW2=$1; shift
NAME=''
VISIBILITY=public
PROJECT_SCOPED=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --name|--visibility)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            if [ "$1" = --name ]; then NAME=$2; else VISIBILITY=$2; fi
            shift 2 ;;
        --project-scoped) PROJECT_SCOPED=true; shift ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$VISIBILITY" in public|community) ;; *) usage >&2; exit 2 ;; esac
for executable in openstack python3; do
    command -v "$executable" >/dev/null || { echo "Required executable not found: $executable" >&2; exit 2; }
done
METADATA=$(python3 - "$QCOW2" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
image = Path(sys.argv[1])
info = json.loads(image.with_name('image-info.json').read_text())
if info['file'] != image.name:
    raise SystemExit('image-info.json names a different image')
digest = hashlib.sha256()
with image.open('rb') as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
        digest.update(chunk)
if digest.hexdigest() != info['sha256']:
    raise SystemExit('image checksum does not match image-info.json')
print(info['agent_version'], info['agent_sha256'])
PY
)
read -r AGENT_VERSION AGENT_SHA256 <<< "$METADATA"
if "$PROJECT_SCOPED"; then
    openstack token issue -f json | python3 -c 'import json,sys; token=json.load(sys.stdin); sys.exit(0 if token.get("project_id") else "--project-scoped requires effective project-scoped OpenStack credentials")'
fi
NAME=${NAME:-waygate-gateway:$AGENT_VERSION-ubuntu-24.04}
IMAGE_ID=$(openstack image create "$NAME" --disk-format qcow2 --container-format bare \
    --file "$QCOW2" "--$VISIBILITY" --property waygate_agent=prebuilt \
    --property "waygate_agent_version=$AGENT_VERSION" --property "waygate_agent_sha256=$AGENT_SHA256" \
    --property os_type=linux --property os_distro=ubuntu -f value -c id)
printf '%s\n' "$IMAGE_ID"
printf 'PUT /v1/admin/resource-policies/waygate.image {"resource_id":"%s"}\n' "$IMAGE_ID"
echo 'Set [waygate] agent_install_mode = "prebuilt" (Kolla: waygate_agent_install_mode).'
