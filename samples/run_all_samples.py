#!/usr/bin/env python3
"""Bootstrap dependencies and run every sample scan once.

Outputs are written to samples/output/<timestamp>/ with:
- one JSON result per scan target
- command logs
- summary.json
- summary.md
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


@dataclass
class ScanResult:
    name: str
    kind: str
    command: list[str]
    output_file: str
    log_file: str
    exit_code: int
    status: str
    started_at: str
    finished_at: str
    duration_seconds: float


ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
OUTPUT_ROOT = SAMPLES_DIR / "output"
VENV_DIR = ROOT / ".venv"
VENV_BIN = VENV_DIR / "bin"
PYTHON_BIN = VENV_BIN / "python"
PIP_BIN = VENV_BIN / "pip"
APPSEC_BIN = VENV_BIN / "appsec"


def run_cmd(
    cmd: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> tuple[int, float]:
    started = time.time()
    proc = subprocess.run(
        list(cmd),
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    elapsed = time.time() - started
    log_path.write_text(proc.stdout, encoding="utf-8")
    return proc.returncode, elapsed


def wait_for_port(host: str, port: int, timeout_seconds: float = 15.0) -> bool:
    end = time.time() + timeout_seconds
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.75)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.2)
    return False


def ensure_venv_and_deps(run_dir: Path, env: dict[str, str]) -> None:
    if not PYTHON_BIN.exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], cwd=str(ROOT), check=True)

    bootstrap_log = run_dir / "bootstrap.log"
    with bootstrap_log.open("w", encoding="utf-8") as handle:
        for cmd in (
            [str(PIP_BIN), "install", "--upgrade", "pip"],
            [str(PIP_BIN), "install", "-e", "."],
            [str(PIP_BIN), "install", "-r", str(SAMPLES_DIR / "requirements.txt")],
        ):
            handle.write(f"$ {' '.join(cmd)}\n")
            proc = subprocess.run(
                cmd,
                cwd=str(ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            handle.write(proc.stdout)
            handle.write("\n")
            if proc.returncode != 0:
                raise RuntimeError(f"Dependency setup failed for command: {' '.join(cmd)}")


def main() -> int:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = OUTPUT_ROOT / timestamp
    run_dir.mkdir(parents=True, exist_ok=False)

    env = dict(os.environ)
    env["PATH"] = f"{VENV_BIN}:{env.get('PATH', '')}"
    env["PYTHONUNBUFFERED"] = "1"

    print(f"[setup] run directory: {run_dir}")
    ensure_venv_and_deps(run_dir, env)

    scan_results: list[ScanResult] = []
    output_files = run_dir / "results"
    logs_dir = run_dir / "logs"
    output_files.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    file_scans: list[tuple[str, list[str], str]] = [
        ("sast_python_command_injection", ["--sast"], "samples/sast/python_command_injection"),
        ("sast_python_eval_exec_injection", ["--sast"], "samples/sast/python_eval_exec_injection"),
        ("sast_python_sql_injection", ["--sast"], "samples/sast/python_sql_injection"),
        ("sast_python_path_traversal", ["--sast"], "samples/sast/python_path_traversal"),
        ("sast_python_weak_crypto", ["--sast"], "samples/sast/python_weak_crypto"),
        ("sast_python_safe_patterns", ["--sast"], "samples/sast/python_safe_patterns"),
        ("sca_python_vulnerable_deps", ["--sca"], "samples/sca/python_vulnerable_deps"),
        ("sca_python_safe_deps", ["--sca"], "samples/sca/python_safe_deps"),
        ("iac_terraform_public_ingress", ["--iac"], "samples/iac/terraform_public_ingress"),
        ("iac_terraform_unencrypted_storage", ["--iac"], "samples/iac/terraform_unencrypted_storage"),
        ("iac_terraform_safe_baseline", ["--iac"], "samples/iac/terraform_safe_baseline"),
        ("combined_flask_vulnerable_app_sast", ["--sast"], "samples/combined/flask_vulnerable_app"),
        ("combined_flask_safe_app_sast", ["--sast"], "samples/combined/flask_safe_app"),
        (
            "combined_app_with_vulnerable_requirements_sast_sca",
            ["--sast", "--sca"],
            "samples/combined/app_with_vulnerable_requirements",
        ),
        (
            "combined_app_with_safe_terraform_sast_iac",
            ["--sast", "--iac"],
            "samples/combined/app_with_safe_terraform",
        ),
    ]

    for name, flags, target in file_scans:
        started = datetime.now(timezone.utc)
        output_path = output_files / f"{name}.json"
        log_path = logs_dir / f"{name}.log"
        cmd = [
            str(APPSEC_BIN),
            "scan",
            target,
            *flags,
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
        print(f"[scan:file] {name}")
        code, elapsed = run_cmd(cmd, cwd=ROOT, env=env, log_path=log_path)
        finished = datetime.now(timezone.utc)
        scan_results.append(
            ScanResult(
                name=name,
                kind="filesystem",
                command=cmd,
                output_file=str(output_path.relative_to(SAMPLES_DIR)),
                log_file=str(log_path.relative_to(SAMPLES_DIR)),
                exit_code=code,
                status="ok" if code in (0, 1) else "error",
                started_at=started.isoformat(),
                finished_at=finished.isoformat(),
                duration_seconds=round(elapsed, 3),
            )
        )

    dast_targets: list[tuple[str, list[str], int, str, list[str]]] = [
        (
            "dast_simple_headers_app",
            [str(PYTHON_BIN), "samples/dast/simple_headers_app/app.py"],
            5101,
            "http://127.0.0.1:5101",
            [],
        ),
        (
            "dast_simple_reflection_app",
            [str(PYTHON_BIN), "samples/dast/simple_reflection_app/app.py"],
            5102,
            "http://127.0.0.1:5102",
            [],
        ),
        (
            "dast_simple_error_leak_app",
            [str(PYTHON_BIN), "samples/dast/simple_error_leak_app/app.py"],
            5103,
            "http://127.0.0.1:5103",
            [],
        ),
        (
            "dast_simple_cors_app",
            [str(PYTHON_BIN), "samples/dast/simple_cors_app/app.py"],
            5104,
            "http://127.0.0.1:5104",
            [],
        ),
        (
            "dast_simple_api_target",
            [
                str(VENV_BIN / "uvicorn"),
                "app:app",
                "--app-dir",
                "samples/dast/simple_api_target",
                "--host",
                "127.0.0.1",
                "--port",
                "5105",
            ],
            5105,
            "http://127.0.0.1:5105",
            ["--openapi", "samples/dast/simple_api_target/openapi.yaml"],
        ),
        (
            "combined_flask_vulnerable_app_dast",
            [str(PYTHON_BIN), "samples/combined/flask_vulnerable_app/app.py"],
            5201,
            "http://127.0.0.1:5201",
            [],
        ),
        (
            "combined_flask_safe_app_dast",
            [str(PYTHON_BIN), "samples/combined/flask_safe_app/app.py"],
            5202,
            "http://127.0.0.1:5202",
            [],
        ),
        (
            "combined_app_with_vulnerable_requirements_dast",
            [str(PYTHON_BIN), "samples/combined/app_with_vulnerable_requirements/app.py"],
            5203,
            "http://127.0.0.1:5203",
            [],
        ),
        (
            "combined_app_with_safe_terraform_dast",
            [str(PYTHON_BIN), "samples/combined/app_with_safe_terraform/app.py"],
            5204,
            "http://127.0.0.1:5204",
            [],
        ),
    ]

    for name, serve_cmd, port, url, extra_flags in dast_targets:
        started = datetime.now(timezone.utc)
        output_path = output_files / f"{name}.json"
        scan_log = logs_dir / f"{name}.log"
        server_log = logs_dir / f"{name}.server.log"
        print(f"[scan:dast] {name}")

        with server_log.open("w", encoding="utf-8") as srv_handle:
            server = subprocess.Popen(
                serve_cmd,
                cwd=str(ROOT),
                env=env,
                stdout=srv_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                if not wait_for_port("127.0.0.1", port):
                    scan_log.write_text(
                        f"Server failed to start on port {port}.\nCommand: {' '.join(serve_cmd)}\n",
                        encoding="utf-8",
                    )
                    finished = datetime.now(timezone.utc)
                    scan_results.append(
                        ScanResult(
                            name=name,
                            kind="dast_http",
                            command=[*serve_cmd, " && ", str(APPSEC_BIN), "scan", url, "--dast", *extra_flags],
                            output_file=str(output_path.relative_to(SAMPLES_DIR)),
                            log_file=str(scan_log.relative_to(SAMPLES_DIR)),
                            exit_code=2,
                            status="error",
                            started_at=started.isoformat(),
                            finished_at=finished.isoformat(),
                            duration_seconds=round((finished - started).total_seconds(), 3),
                        )
                    )
                    continue

                cmd = [
                    str(APPSEC_BIN),
                    "scan",
                    url,
                    "--dast",
                    *extra_flags,
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                ]
                code, elapsed = run_cmd(cmd, cwd=ROOT, env=env, log_path=scan_log)
                finished = datetime.now(timezone.utc)
                scan_results.append(
                    ScanResult(
                        name=name,
                        kind="dast_http",
                        command=cmd,
                        output_file=str(output_path.relative_to(SAMPLES_DIR)),
                        log_file=str(scan_log.relative_to(SAMPLES_DIR)),
                        exit_code=code,
                        status="ok" if code in (0, 1) else "error",
                        started_at=started.isoformat(),
                        finished_at=finished.isoformat(),
                        duration_seconds=round(elapsed, 3),
                    )
                )
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)

    summary_json = run_dir / "summary.json"
    summary_md = run_dir / "summary.md"
    latest_txt = OUTPUT_ROOT / "LATEST_RUN.txt"

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_directory": str(run_dir.relative_to(SAMPLES_DIR)),
        "counts": {
            "total": len(scan_results),
            "ok": sum(1 for r in scan_results if r.status == "ok"),
            "error": sum(1 for r in scan_results if r.status == "error"),
        },
        "results": [asdict(r) for r in scan_results],
    }
    summary_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Sample Scan Summary",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Run directory: `{payload['run_directory']}`",
        f"- Total scans: `{payload['counts']['total']}`",
        f"- OK (exit 0/1): `{payload['counts']['ok']}`",
        f"- Errors (exit 2+): `{payload['counts']['error']}`",
        "",
        "## Per-scan Results",
        "",
    ]
    for result in scan_results:
        lines.append(
            f"- `{result.name}` [{result.kind}] -> status=`{result.status}` "
            f"exit=`{result.exit_code}` output=`{result.output_file}` log=`{result.log_file}`"
        )
    summary_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    latest_txt.write_text(str(run_dir.relative_to(SAMPLES_DIR)) + "\n", encoding="utf-8")

    print(f"[done] summary: {summary_json}")
    print(f"[done] markdown: {summary_md}")
    print(f"[done] latest pointer: {latest_txt}")
    return 0 if payload["counts"]["error"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
