import subprocess

import pytest

from waygate.network import LinuxNetworkControl, NetworkUnavailable


def test_ambiguous_active_generations_fail_closed():
    def run(argv):
        return subprocess.CompletedProcess(argv, 0, b"-P INPUT ACCEPT\n-A INPUT -j WAYGATE_INPUT_A\n-A INPUT -j WAYGATE_INPUT_B\n", b"")
    with pytest.raises(NetworkUnavailable, match="generation drift"):
        LinuxNetworkControl(run)._active_generation("INPUT", "WAYGATE_INPUT")


def test_policy_line_does_not_break_stage_order_check():
    def run(argv):
        return subprocess.CompletedProcess(argv, 0, b"-P INPUT ACCEPT\n-A INPUT -j WAYGATE_STAGE_IN\n", b"")
    LinuxNetworkControl(run)._verify_stage_jump("INPUT", "WAYGATE_STAGE_IN")
