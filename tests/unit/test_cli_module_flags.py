from __future__ import annotations

from apps.cli.commands import build_parser


def test_scan_flag_sca_sets_sca_module() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan", ".", "--sca"])
    assert args.module_choice == "sca"


def test_scan_flag_iac_sets_iac_module() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan", ".", "--iac"])
    assert args.module_choice == "iac"


def test_scan_flag_all_sets_all_modules_choice() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan", ".", "--all"])
    assert args.module_choice == "all"
