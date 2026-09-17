"""Tests for Waygate Kolla-Ansible packaging and lifecycle assets."""

from __future__ import annotations

import subprocess
import tomllib
import zipfile
from pathlib import Path

import jinja2
import yaml

REPO_ROOT = Path(__file__).parent.parent
KOLLA_DIR = REPO_ROOT / "deploy" / "kolla"
ROLE_DIR = KOLLA_DIR / "ansible" / "roles" / "waygate"


def test_kolla_required_assets_exist():
    assert KOLLA_DIR.exists()
    assert ROLE_DIR.is_dir()
    assert not (KOLLA_DIR / "pyproject.toml").exists()
    assert not (KOLLA_DIR / "src" / "waygate_kolla" / "__init__.py").exists()

    required_role_files = [
        "defaults/main.yml",
        "files/validate_image_ref.py",
        "handlers/main.yml",
        "meta/main.yml",
        "templates/waygate.conf.j2",
        "vars/main.yml",
        "tasks/main.yml",
        "tasks/deploy.yml",
        "tasks/reconfigure.yml",
        "tasks/upgrade.yml",
        "tasks/precheck.yml",
        "tasks/pull.yml",
        "tasks/config.yml",
        "tasks/bootstrap_service.yml",
        "tasks/start.yml",
        "tasks/destroy.yml",
        "tasks/loadbalancer.yml",
        "tasks/source_build.yml",
        "tasks/image_precheck.yml",
        "tasks/preconditions.yml",
        "tasks/preconditions_keystone.yml",
        "tasks/preconditions_db.yml",
    ]

    for relative_path in required_role_files:
        path = ROLE_DIR / relative_path
        assert path.exists(), f"Missing required role asset: {relative_path}"


def test_root_package_metadata_and_image_default():
    pyproject_data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject_data["project"]
    service_dependencies = project["optional-dependencies"]["service"]

    assert project["name"] == "waygate"
    assert project["version"] == "0.1.3"
    assert project["requires-python"] == ">=3.12"
    assert "dependencies" not in project
    assert "ansible" not in "\n".join(service_dependencies).lower()
    assert "fastapi==0.125.0" in service_dependencies
    assert pyproject_data["tool"]["hatch"]["build"]["targets"]["wheel"]["shared-data"] == {
        "deploy/kolla/ansible/roles/waygate": "share/kolla-ansible/ansible/roles/waygate"
    }

    defaults_yaml = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults_yaml["waygate_image_tag"] == "0.1.2"


def test_all_yaml_files_parse():
    for yml_file in ROLE_DIR.rglob("*.yml"):
        content = yml_file.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert parsed is not None or yml_file.name == "main.yml", f"YAML file parsed to None or empty: {yml_file}"


def test_jinja_templates_compile():
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    for template_file in (ROLE_DIR / "templates").glob("*.j2"):
        content = template_file.read_text(encoding="utf-8")
        assert env.parse(content) is not None


def test_root_wheel_build_and_install_includes_kolla_role(tmp_path: Path):
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    project_version = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]

    res = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"uv build failed: {res.stderr}"

    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    wheel_path = wheels[0]
    assert f"waygate-{project_version}" in wheel_path.name

    with zipfile.ZipFile(wheel_path, "r") as zf:
        namelist = zf.namelist()
        data_prefix = f"waygate-{project_version}.data/data/share/kolla-ansible/ansible/roles/waygate/"
        role_files = [name for name in namelist if name.startswith(data_prefix)]
        assert role_files, "No shared-data role files found in wheel"
        assert any(name.endswith("defaults/main.yml") for name in role_files)
        assert any(name.endswith("tasks/main.yml") for name in role_files)
        assert any(name.endswith("templates/waygate.conf.j2") for name in role_files)

        metadata_member = next(name for name in namelist if name.endswith(".dist-info/METADATA"))
        metadata = zf.read(metadata_member).decode("utf-8")
        requires_dist = [line for line in metadata.splitlines() if line.startswith("Requires-Dist:")]
        assert requires_dist
        assert all("; extra ==" in requirement for requirement in requires_dist)
        assert "Requires-Dist: fastapi==0.125.0; extra == 'service'" in metadata
        assert "ansible" not in metadata.lower()

    venv_dir = tmp_path / "venv"
    res_venv = subprocess.run(["uv", "venv", str(venv_dir)], capture_output=True, text=True)
    assert res_venv.returncode == 0, f"uv venv failed: {res_venv.stderr}"

    venv_python = venv_dir / "bin" / "python"
    res_inst = subprocess.run(
        ["uv", "pip", "install", "--python", str(venv_python), "--no-deps", str(wheel_path)],
        capture_output=True,
        text=True,
    )
    assert res_inst.returncode == 0, f"uv pip install failed: {res_inst.stderr}"

    installed_role = venv_dir / "share" / "kolla-ansible" / "ansible" / "roles" / "waygate"
    assert (installed_role / "defaults" / "main.yml").is_file()
    assert (installed_role / "tasks" / "main.yml").is_file()
    assert (installed_role / "templates" / "waygate.conf.j2").is_file()

    res_uninst = subprocess.run(
        ["uv", "pip", "uninstall", "--python", str(venv_python), "waygate"],
        capture_output=True,
        text=True,
    )
    assert res_uninst.returncode == 0, f"uv pip uninstall failed: {res_uninst.stderr}"
    remaining_files = list(installed_role.glob("**/*")) if installed_role.exists() else []
    assert not [path for path in remaining_files if path.is_file()], "Uninstall left behind role files"
