import os
import sys
from unittest.mock import MagicMock, patch
import pytest

from check_env import is_running_as_admin, verify_environment


def test_is_running_as_admin_posix():
    with patch("os.name", "posix"):
        with patch("os.geteuid", return_value=0):
            assert is_running_as_admin() is True

        with patch("os.geteuid", return_value=1000):
            assert is_running_as_admin() is False


@patch("check_env.get_scapy_version", return_value="2.7.0")
@patch(
    "check_env.list_interfaces_with_scapy",
    return_value=([{"name": "eth0", "ip": "192.168.1.5"}], ["eth0"]),
)
@patch("check_env.check_capture_prerequisites", return_value=[])
@patch("check_env.test_packet_capture", return_value=True)
@patch("check_env.is_running_as_admin", return_value=True)
def test_verify_environment_success(
    mock_admin, mock_cap, mock_prereq, mock_ifaces, mock_scapy
):
    exit_code = verify_environment(quiet=True)
    assert exit_code == 0


@patch("check_env.get_scapy_version", return_value=None)
def test_verify_environment_missing_scapy(mock_scapy):
    exit_code = verify_environment(quiet=True)
    assert exit_code == 2
