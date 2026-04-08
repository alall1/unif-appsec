from __future__ import annotations

from pathlib import Path

from modules.sca.parsers.requirements_txt import parse_requirements_txt


def test_requirements_txt_parses_pins(tmp_path: Path) -> None:
    p = tmp_path / "requirements.txt"
    p.write_text(
        "\n".join(
            [
                "# comment",
                "requests==2.31.0",
                "Flask==3.0.0  # inline",
                "git+https://example.invalid/x#egg=y",
                "numpy>=1.0",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    pkgs, warnings = parse_requirements_txt(p)
    assert [(x.package_name, x.package_version) for x in pkgs] == [("requests", "2.31.0"), ("Flask", "3.0.0")]
    assert any("direct URL/VCS" in w for w in warnings)
    assert any("only name==version supported" in w for w in warnings)

