"""Waygate Kolla-Ansible role contract tests.

Restores the HAProxy, Valkey, lifecycle-dispatch, and image-validator
coverage for the Waygate role that used to live in Afterglow's
scripts/kolla-contract.test.js (see git show 249dd697:scripts/kolla-contract.test.js
in the openstack-afterglow/afterglow repository for the pre-migration
baseline). That aggregate file also asserted against Afterglow-owned,
cross-service files (deploy/kolla/site.yml, deploy/kolla/globals.afterglow.sample.yml,
deploy/kolla/inventory/*.sample, deploy/kolla/install.sh/uninstall.sh) that do
not exist in this repository post-migration; those assertions are Afterglow's
responsibility to own/restore and are intentionally NOT duplicated here since
doing so would require a filesystem dependency on the Afterglow repo. Only
the assertions that are fully self-contained within this repo's own
deploy/kolla/ansible/roles/waygate/ tree are restored below.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROLE_DIR = REPO_ROOT / "deploy" / "kolla" / "ansible" / "roles" / "waygate"


def _read(relative_path: str) -> str:
    return (ROLE_DIR / relative_path).read_text(encoding="utf-8")


def test_lifecycle_dispatcher_preserves_stock_actions_and_tag_isolation() -> None:
    dispatcher = _read("tasks/main.yml")

    assert "tags: always" not in dispatcher
    assert "'config_validate', 'stop', 'deploy-containers', 'check'" in dispatcher
    assert re.search(r"when: kolla_action \| default\('deploy'\) in \[.*'config'\]", dispatcher)


def test_lifecycle_actions_include_tasks_in_the_expected_order() -> None:
    deploy = _read("tasks/deploy.yml")
    reconfigure = _read("tasks/reconfigure.yml")
    upgrade = _read("tasks/upgrade.yml")
    pull = _read("tasks/pull.yml")
    precheck = _read("tasks/precheck.yml")

    assert deploy.index("Include precheck tasks") < deploy.index("Include precondition tasks")
    assert reconfigure.index("Include precheck tasks") < reconfigure.index("Include config tasks")
    assert upgrade.index("Include pull tasks") < upgrade.index("Include bootstrap service tasks")
    assert pull.index("Include Waygate image precheck tasks") < pull.index("Pull | Pull Waygate images")
    assert "include_tasks: image_precheck.yml" in precheck
    assert "include_tasks: image_precheck.yml" in pull


def test_validates_every_configured_runtime_image_reference_before_mutation() -> None:
    image_precheck = _read("tasks/image_precheck.yml")
    validator = _read("files/validate_image_ref.py")

    assert "Validate enabled Waygate image references" in image_precheck
    assert "Inspect enabled remote Waygate image manifests" in image_precheck
    assert 'loop: "{{ waygate_services | dict2items }}"' in image_precheck
    assert '- "{{ item.value.image }}"' in image_precheck
    assert '- "{{ waygate_source_mode | default(false) | bool | lower }}"' in image_precheck
    assert "- manifest" in image_precheck
    assert "- inspect" in image_precheck
    assert "failed_when: false" not in image_precheck
    assert "waygate_api_image }}:{{ waygate_image_tag" not in image_precheck
    assert "@sha256:[0-9a-f]{64}" in validator
    assert "afterglow-local/waygate-" in validator


def test_pull_and_start_use_stock_docker_module_semantics() -> None:
    pull = _read("tasks/pull.yml")
    start = _read("tasks/start.yml")

    assert "community.docker.docker_image" in pull
    assert re.search(r"source:\s*pull", pull)
    assert re.search(r"force_source:\s*true", pull)
    assert re.search(r"no_log:\s*true", pull)
    assert re.search(r'loop:\s*"\{\{\s*waygate_services\s*\|\s*dict2items\s*\}\}"', pull)
    assert re.search(r"not\s*\(waygate_source_mode\s*\|\s*default\(false\)\s*\|\s*bool\)", pull)
    assert re.search(
        r'pull:\s*"\{\{\s*\'never\'\s+if\s+\(waygate_source_mode\s*\|\s*default\(false\)\s*\|\s*bool\)\s+else\s+\'always\'\s*\}\}"',
        start,
    )


def test_public_hostname_routed_by_external_haproxy_without_disturbing_internal_endpoint() -> None:
    defaults = _read("defaults/main.yml")
    precheck = _read("tasks/precheck.yml")
    loadbalancer = _read("tasks/loadbalancer.yml")

    assert re.search(r"^waygate_public_haproxy_enabled: false$", defaults, re.MULTILINE)
    assert re.search(r'^waygate_public_haproxy_fqdn: ""$', defaults, re.MULTILINE)
    assert (
        'waygate_haproxy_services: "{{ waygate_services | combine(waygate_public_haproxy_services, recursive=True) }}"'
        in defaults
    )
    assert re.search(r"waygate-public:\n\s+group: waygate", defaults)
    assert 'external_fqdn: "{{ waygate_public_haproxy_fqdn }}"' in defaults
    assert 'port: "{{ waygate_api_port }}"' in defaults
    # The internal waygate-api entry must remain non-external so internal/admin
    # Keystone endpoints keep the internal VIP listener.
    assert re.search(
        r'waygate-api:\n\s+enabled: "\{\{ enable_waygate_api \| bool \}\}"\n\s+external: false',
        defaults,
    )

    assert "Validate Waygate public route hostname" in precheck
    assert (
        "- (waygate_public_endpoint_url | regex_replace('/$', '')) == "
        "('https://' ~ waygate_public_haproxy_fqdn)" in precheck
    )
    assert "waygate-public.cfg" in loadbalancer
    assert "external-frontend-map" in loadbalancer
    assert 'project_services: "{{ waygate_haproxy_services }}"' in loadbalancer


def test_valkey_dependency_required_and_standalone_redis_rejected() -> None:
    defaults = _read("defaults/main.yml")
    precheck = _read("tasks/precheck.yml")

    assert "waygate_valkey_host: \"{{ 'api' | kolla_address(groups['valkey'][0]) }}\"" in defaults
    assert 'waygate_valkey_port: "{{ valkey_server_port }}"' in defaults
    assert "waygate_valkey_password:" in defaults
    assert re.search(r"waygate_valkey_password:.*valkey_master_password", defaults)
    assert "waygate_redis_db_index: 6" in defaults
    assert (
        'waygate_redis_url: "redis://default:{{ waygate_valkey_password }}'
        '@{{ waygate_valkey_host }}:{{ waygate_valkey_port }}/{{ waygate_redis_db_index }}"' in defaults
    )

    assert "name: Precheck | Verify stock Kolla Valkey dependency" in precheck
    assert "enable_valkey | default(false) | bool" in precheck
    assert "groups.get('valkey', []) | length > 0" in precheck
    assert "valkey_master_password is defined and valkey_master_password | length > 0" in precheck
    assert "when: enable_waygate | default(false) | bool" in precheck
    assert "run_once: true" in precheck
    assert "tags: precheck" in precheck
    assert "Deploy stock Kolla Valkey before enabling waygate; no plugin Redis fallback exists" in precheck


def test_data_plane_and_openstack_topology_derived_from_kolla_variables() -> None:
    defaults = _read("defaults/main.yml")
    template = _read("templates/waygate.conf.j2")
    database = _read("tasks/preconditions_db.yml")

    assert 'waygate_database_address: "{{ database_address }}"' in defaults
    assert 'waygate_database_port: "{{ database_port }}"' in defaults
    assert 'waygate_database_admin_user: "{{ database_user }}"' in defaults
    assert 'waygate_keystone_auth_url: "{{ keystone_internal_url }}"' in defaults
    assert 'waygate_keystone_project_domain_name: "{{ default_project_domain_name }}"' in defaults
    assert 'waygate_keystone_user_domain_name: "{{ default_user_domain_name }}"' in defaults
    assert 'waygate_keystone_region_name: "{{ openstack_region_name }}"' in defaults
    assert re.search(
        r"waygate_keystone_interface: \"\{\{\s*openstack_interface\s*\|\s*default\('internal'\)\s*\}\}\"",
        defaults,
    )
    assert 'auth_url = "{{ waygate_keystone_auth_url }}"' in template
    assert 'url = "{{ waygate_database_url }}"' in template
    assert 'login_host: "{{ waygate_database_address }}"' in database


def test_topology_fallbacks_use_kolla_internal_vip_and_interface_defaults() -> None:
    defaults = _read("defaults/main.yml")

    assert re.search(
        r"waygate_keystone_interface: \"\{\{ openstack_interface \| default\('internal'\) \}\}\"",
        defaults,
    )
    assert (
        "waygate_internal_endpoint_url: \"{{ internal_protocol | default('http') }}"
        '://{{ kolla_internal_fqdn | default(kolla_internal_vip_address) }}:{{ waygate_api_port }}"' in defaults
    )


def test_extracted_service_health_check_uses_python_available_in_published_images() -> None:
    defaults = _read("defaults/main.yml")

    assert re.search(
        r"healthcheck:\n\s+test: \[\"CMD\", \"python\", \"-c\", \"from urllib\.request import urlopen;",
        defaults,
    )
    assert not re.search(r'test: \["CMD", "curl", "-f"', defaults)
