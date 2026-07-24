import subprocess

import pytest

from afterglow_wg_agent.network import LinuxNetworkControl, NetworkUnavailable


def test_ambiguous_active_generations_fail_closed():
    def run(argv):
        return subprocess.CompletedProcess(argv, 0, b"-P INPUT ACCEPT\n-A INPUT -j AFTERGLOW_INPUT_A\n-A INPUT -j AFTERGLOW_INPUT_B\n", b"")
    with pytest.raises(NetworkUnavailable, match="generation drift"):
        LinuxNetworkControl(run)._active_generation("INPUT", "AFTERGLOW_INPUT")


def test_policy_line_does_not_break_stage_order_check():
    def run(argv):
        return subprocess.CompletedProcess(argv, 0, b"-P INPUT ACCEPT\n-A INPUT -j AFTERGLOW_STAGE_IN\n", b"")
    LinuxNetworkControl(run)._verify_stage_jump("INPUT", "AFTERGLOW_STAGE_IN")
