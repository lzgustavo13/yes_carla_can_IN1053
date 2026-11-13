"""Exercise lab scripts with fake commands; never start CARLA or change a network."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def shell_lab(tmp_path):
    commands = tmp_path / "bin"
    commands.mkdir()
    calls = tmp_path / "calls.jsonl"
    simulator = tmp_path / "carla installation"
    simulator.mkdir()
    # The recorder is an absolute interpreter path, independent of the fake PATH.
    recorder = f"""#!{sys.executable}
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['SCRIPT_TEST_LOG'], 'a') as stream:
    stream.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
if name == 'ip' and sys.argv[1:4] == ['link', 'show', 'dev']:
    sys.exit(0 if os.environ.get('SCRIPT_TEST_EXISTING') else 1)
if name == 'cangw' and os.environ.get('SCRIPT_TEST_NETWORK_FAILURE'):
    sys.exit(1)
sys.exit(1 if name == 'pgrep' else 0)
"""
    for name in ("conda", "ip", "modprobe", "cangw", "sleep", "pgrep", "apt-get", "wget", "curl", "tar"):
        path = commands / name
        path.write_text(recorder)
        path.chmod(0o755)
    sudo = commands / "sudo"
    sudo.write_text('#!/bin/bash\nif [[ "$1" != -v ]]; then exec "$@"; fi\n')
    sudo.chmod(0o755)
    executable = simulator / "CarlaUE4.sh"
    executable.write_text(recorder)
    executable.chmod(0o755)
    env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}",
               CARLA_FOLDER_NAME=str(simulator), CONDA_ENV_NAME="review_env",
               SCRIPT_TEST_LOG=str(calls), VK_ICD_FILENAMES="test-driver")
    return tmp_path, env, calls


def run_script(name, env, *args):
    return subprocess.run(["bash", str(ROOT / name), *args], cwd=ROOT,
                          env=env, text=True, capture_output=True, timeout=15)


def read_calls(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.parametrize("args", [
    ("--res", "invalid"), ("--fps", "0"), ("--camera-fps", "-1"),
    ("--performance", "--map", "Town02"),
])
def test_invalid_startup_arguments_have_no_external_effects(shell_lab, args):
    _, env, calls = shell_lab
    result = run_script("1_up_environment.sh", env, *args)
    assert result.returncode == 1
    assert not read_calls(calls)


def test_performance_startup_keeps_arguments_and_two_echo_routes(shell_lab):
    _, env, calls = shell_lab
    result = run_script("1_up_environment.sh", env, "--performance")
    assert result.returncode == 0, result.stderr
    entries = read_calls(calls)
    server = next(row for row in entries if row[0] == "CarlaUE4.sh")
    assert "-quality-level=Low" in server and "-ResX=800" in server and "-ResY=450" in server
    client = next(row for row in entries if any(value.endswith("/CARLA_client_module.py") for value in row))
    for value in ("review_env", "--res", "800x450", "--camera-fps", "30", "--map", "Town02_Opt", "--minimal-map"):
        assert value in client
    assert [row for row in entries if row[0] == "cangw"] == [
        ["cangw", "-A", "-s", "vcan1", "-d", "vcan0", "-e"],
        ["cangw", "-A", "-s", "vcan0", "-d", "vcan1", "-e"],
    ]


def test_existing_interfaces_are_not_modified(shell_lab):
    _, env, calls = shell_lab
    env["SCRIPT_TEST_EXISTING"] = "1"
    result = run_script("1_up_environment.sh", env, "--performance")
    assert result.returncode == 1
    assert "already exist" in result.stderr
    assert all(row[0] == "ip" and row[1:4] == ["link", "show", "dev"] for row in read_calls(calls))


def test_failed_network_setup_removes_only_created_interfaces_and_never_starts_carla(shell_lab):
    _, env, calls = shell_lab
    env["SCRIPT_TEST_NETWORK_FAILURE"] = "1"
    result = run_script("1_up_environment.sh", env, "--performance")
    assert result.returncode == 1
    entries = read_calls(calls)
    assert not any(row[0] == "CarlaUE4.sh" for row in entries)
    deletions = [row for row in entries if row[:3] == ["ip", "link", "delete"]]
    assert deletions == [["ip", "link", "delete", "vcan1"], ["ip", "link", "delete", "vcan0"]]
    assert not any("-F" in row for row in entries)


@pytest.mark.parametrize("script,feature", [
    ("scripts/demo_replay.sh", "replay"),
    ("scripts/demo_fabrication.sh", "fabrication"),
    ("scripts/demo_privacy_leakage.sh", "privacy_leakage"),
])
def test_attack_shortcuts_honor_environment_and_forward_user_arguments(shell_lab, script, feature):
    _, env, calls = shell_lab
    result = run_script(script, env, "--help")
    assert result.returncode == 0, result.stderr
    command = next(row for row in read_calls(calls) if row[0] == "conda")
    assert command[command.index("-n") + 1] == "review_env"
    assert command[command.index("--feature") + 1] == feature
    assert command[-1] == "--help"


def test_shutdown_preserves_interfaces_when_gateway_recovery_is_pending(shell_lab):
    folder, env, calls = shell_lab
    script = folder / "2_down_environment.sh"
    shutil.copy2(ROOT / script.name, script)
    (folder / "results").mkdir()
    journal = folder / "results/can_gateway_state.json"
    journal.write_text('{"recovery": "pending"}')
    result = subprocess.run(["bash", str(script)], cwd=folder, env=env,
                            text=True, capture_output=True, timeout=5)
    assert result.returncode == 1
    assert "--restore" in result.stderr
    assert journal.read_text() == '{"recovery": "pending"}'
    assert not read_calls(calls)


@pytest.mark.parametrize("script", ["0_install_dependencies.sh", "1_up_environment.sh", "2_down_environment.sh"])
def test_environment_help_is_side_effect_free(shell_lab, script):
    _, env, calls = shell_lab
    result = run_script(script, env, "--help")
    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert not read_calls(calls)


def test_installer_preserves_existing_carla_and_honors_environment(shell_lab):
    _, env, calls = shell_lab
    result = run_script("0_install_dependencies.sh", env)
    assert result.returncode == 0, result.stderr
    assert "already installed" in result.stdout
    entries = read_calls(calls)
    install = next(row for row in entries if row[:3] == ["conda", "run", "--no-capture-output"])
    assert install[install.index("-n") + 1] == "review_env"
    assert "pip" in install and "requirements.txt" in install
    assert not any(row[0] in {"wget", "curl", "CarlaUE4.sh"} for row in entries)
