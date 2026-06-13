"""Unit tests for mcp-reva tool-group CLI flags and launcher wiring."""

from unittest.mock import MagicMock

import pytest

from reva_cli.__main__ import _build_parser
from reva_cli.launcher import ReVaLauncher

pytestmark = [pytest.mark.unit]


def test_parser_collects_disable_tool_groups():
    args = _build_parser().parse_args(
        ["--disable-tool-group", "scripting", "--disable-tool-group", "diff"])
    assert args.disable_tool_group == ["scripting", "diff"]
    assert args.tool_group is None


def test_parser_collects_enable_tool_groups():
    args = _build_parser().parse_args(["--tool-group", "core-analysis"])
    assert args.tool_group == ["core-analysis"]
    assert args.disable_tool_group is None


def test_parser_rejects_both_lists():
    with pytest.raises(SystemExit):
        _build_parser().parse_args(
            ["--tool-group", "core-analysis", "--disable-tool-group", "scripting"])


def test_launcher_applies_disabled_groups():
    launcher = ReVaLauncher(disabled_tool_groups=["scripting", "diff"])
    java_launcher = MagicMock()
    launcher._apply_tool_group_config(java_launcher)
    java_launcher.setDisabledToolGroups.assert_called_once_with("scripting,diff")
    java_launcher.setEnabledToolGroups.assert_not_called()


def test_launcher_applies_enabled_groups():
    launcher = ReVaLauncher(enabled_tool_groups=["core-analysis"])
    java_launcher = MagicMock()
    launcher._apply_tool_group_config(java_launcher)
    java_launcher.setEnabledToolGroups.assert_called_once_with("core-analysis")
    java_launcher.setDisabledToolGroups.assert_not_called()


def test_launcher_applies_nothing_when_unset():
    launcher = ReVaLauncher()
    java_launcher = MagicMock()
    launcher._apply_tool_group_config(java_launcher)
    java_launcher.setDisabledToolGroups.assert_not_called()
    java_launcher.setEnabledToolGroups.assert_not_called()
