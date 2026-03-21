from pathlib import Path
import json
import tempfile

from minisast.scanner import scan_file, scan_path


def main():
    bad_code = """
import os
import subprocess
import hashlib

password = "supersecret123"

cmd = input("Enter command: ")
x = cmd

eval("print(1)")
exec("print(2)")
os.system(x)

subprocess.run(cmd, shell=True)
subprocess.Popen(x)
hashlib.md5(b"hello")
hashlib.sha1(b"world")
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "bad.py"
        test_file.write_text(bad_code, encoding="utf-8")

        print("=== scan_file ===")
        findings = scan_file(test_file)
        print(json.dumps([f.to_dict() for f in findings], indent=2))

        print()
        print("=== scan_path ===")
        findings = scan_path(tmp_path)
        print(json.dumps([f.to_dict() for f in findings], indent=2))


if __name__ == "__main__":
    main()
