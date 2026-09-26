#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/build_gateway_image.sh [--builder qemu|openstack] [-o OUTPUT_DIR] [-- <extra packer args>]
Build the Ubuntu 24.04 amd64 gateway image. Default builder: qemu (Linux/KVM).
macOS arm64/QEMU: use -- -var accelerator=tcg -var cpu_model=max.
OpenStack: use --builder openstack -- -var source_image=IMAGE_ID -var flavor=FLAVOR -var network_id=NETWORK_ID
Authenticate OpenStack with OS_CLOUD/clouds.yaml or OS_* variables. The runner must reach the build VM over SSH.
Both builders require Packer and Python 3; only QEMU requires qemu-system-x86_64 and a seed-ISO tool.
EOF
}
REPO=$(cd "$(dirname "$0")/.." && pwd)
BUILDER=qemu
OUTPUT_DIR=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -o|--builder)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            if [ "$1" = -o ]; then OUTPUT_DIR=$2; else BUILDER=$2; fi
            shift 2 ;;
        --) shift; break ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$BUILDER" in
    qemu)
        TEMPLATE="$REPO/deploy/image/packer"
        OUTPUT_DIR=${OUTPUT_DIR:-$REPO/dist/gateway-image}
        REQUIRED='packer python3 qemu-system-x86_64' ;;
    openstack)
        TEMPLATE="$REPO/deploy/image/packer/openstack"
        OUTPUT_DIR=${OUTPUT_DIR:-$REPO/dist/gateway-image-openstack}
        REQUIRED='packer python3' ;;
    *) usage >&2; exit 2 ;;
esac
for executable in $REQUIRED; do
    command -v "$executable" >/dev/null || { echo "Required executable not found: $executable" >&2; exit 2; }
done
OUTPUT_DIR=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT_DIR")
AGENT_DIR="$REPO/waygate/agent"
AGENT_VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$REPO/waygate/__init__.py")
AGENT_SHA256=$(python3 - "$AGENT_DIR" <<'PY'
import hashlib
import sys
from pathlib import Path
root = Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob('*')):
    if path.is_file() and '__pycache__' not in path.parts:
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(path.read_bytes())
print(digest.hexdigest())
PY
)
if [ "$BUILDER" = openstack ]; then mkdir -p "$OUTPUT_DIR"; fi
packer init "$TEMPLATE"
# Keep the sidecar identity consistent with the fixed source/version inputs.
packer build "$@" -var "agent_dir=$AGENT_DIR" -var "agent_version=$AGENT_VERSION" \
    -var "agent_sha256=$AGENT_SHA256" -var "output_directory=$OUTPUT_DIR" "$TEMPLATE"
if [ "$BUILDER" = openstack ]; then
    python3 - "$OUTPUT_DIR" "$AGENT_VERSION" "$AGENT_SHA256" <<'PY'
import json
import sys
from pathlib import Path
output = Path(sys.argv[1])
version, source_hash = sys.argv[2:]
manifest = json.loads((output / 'manifest.json').read_text())
builds = [build for build in manifest['builds']
          if build['packer_run_uuid'] == manifest['last_run_uuid'] and build['builder_type'] == 'openstack']
if len(builds) != 1 or not builds[0]['artifact_id']:
    raise SystemExit('Expected exactly one OpenStack image in the latest Packer manifest run')
image_id = builds[0]['artifact_id']
(output / 'openstack-image-info.json').write_text(json.dumps({
    'image_id': image_id, 'agent_version': version, 'agent_sha256': source_hash,
}, indent=2) + '\n')
print(image_id)
print('PUT /v1/admin/resource-policies/waygate.image ' + json.dumps({'resource_id': image_id}))
print('Set [waygate] agent_install_mode = "prebuilt" (Kolla: waygate_agent_install_mode).')
PY
    exit 0
fi
python3 - "$OUTPUT_DIR" "$AGENT_VERSION" "$AGENT_SHA256" <<'PY'
import json
import sys
from pathlib import Path
output = Path(sys.argv[1])
version, source_hash = sys.argv[2:]
filename = f'waygate-gateway-{version}-ubuntu-24.04-amd64.qcow2'
checksum = (output / (filename + '.sha256')).read_text().split()[0]
(output / 'image-info.json').write_text(json.dumps({
    'file': filename, 'sha256': checksum,
    'agent_version': version, 'agent_sha256': source_hash,
}, indent=2) + '\n')
print(output / filename)
PY
