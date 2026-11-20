#
# SPDX-License-Identifier: Apache-2.0
"""End-to-end demonstration of Bandit review mode.

This script is dependency free and only writes a few lines of Python into
a temporary workspace. It exercises the three review outcomes needed for
security sign-off:

1. moving the working directory leaves every finding reproducible;
2. replacing the scanned input fails at the file layer;
3. changing a controllable plugin config fails at the rule layer.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

BANDIT = [sys.executable, "-m", "bandit"]
APP_SOURCE = (
    "import hashlib\n"
    "import subprocess\n"
    "\n"
    "def build(token):\n"
    "    digest = hashlib.md5(token).hexdigest()\n"
    "    return subprocess.check_output(token, shell=True)\n"
)
SHELL_CONFIG = (
    "shell_injection:\n"
    "  subprocess: [\"subprocess.Popen\"]\n"
    "  shell: [\"os.system\"]\n"
    "  no_shell: []\n"
)

def run_bandit(workdir, *extra):
    cmd = BANDIT + list(extra)
    env = dict(os.environ)
    return subprocess.run(
        cmd, cwd=workdir, env=env, capture_output=True, text=True, check=False
    )


def write_app(workdir):
    src_dir = os.path.join(workdir, "src")
    os.makedirs(src_dir, exist_ok=True)
    path = os.path.join(src_dir, "app.py")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(APP_SOURCE)
    return path


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main():
    base = tempfile.mkdtemp(prefix="bandit-review-")
    try:
        original = os.path.join(base, "workspace")
        write_app(original)
        report = os.path.join(original, "report.json")
        run_bandit(
            original, "--review", "-r", "src", "-f", "json",
            "-o", "report.json", "--exit-zero",
        )
        findings = load_json(report)["results"]
        print("published findings:", len(findings))

        # 1. Moving the directory must keep every finding reproducible.
        moved = os.path.join(base, "relocated")
        shutil.move(original, moved)
        run_bandit(
            moved, "--verify-report", "report.json", "src",
            "-f", "json", "-o", "verify.json", "--exit-zero",
        )
        moved_counts = load_json(os.path.join(moved, "verify.json"))["counts"]
        print("after move:", moved_counts)

        # 2. Replacing the scanned input fails at the file layer.
        changed = os.path.join(base, "changed-input")
        shutil.copytree(moved, changed)
        app = os.path.join(changed, "src", "app.py")
        with open(app, "w", encoding="utf-8") as handle:
            handle.write(APP_SOURCE.replace("token", "identifier"))
        run_bandit(
            changed, "--verify-report", "report.json", "src",
            "-f", "json", "-o", "verify.json", "--exit-zero",
        )
        file_counts = load_json(
            os.path.join(changed, "verify.json"))["counts"]
        print("after input change:", file_counts)

        # 3. Changing a controllable plugin config fails at rule layer.
        reconfigured = os.path.join(base, "changed-config")
        shutil.copytree(moved, reconfigured)
        with open(
            os.path.join(reconfigured, "bandit.yaml"), "w",
            encoding="utf-8",
        ) as handle:
            handle.write(SHELL_CONFIG)
        run_bandit(
            reconfigured, "--verify-report", "report.json", "src",
            "-c", "bandit.yaml", "-f", "json", "-o",
            "verify.json", "--exit-zero",
        )
        rule_outcome = load_json(
            os.path.join(reconfigured, "verify.json"))
        print("after config change:", rule_outcome["counts"])
        rule_failures = [
            item for item in rule_outcome["results"]
            if item["layer"] == "rule"
        ]
        print("rule-layer finding:", rule_failures[0]["test_id"])

        assert moved_counts["reproducible"] == len(findings)
        assert file_counts["file"] == len(findings)
        assert rule_outcome["counts"]["rule"] == 1
        assert rule_failures[0]["test_id"] == "B602"
        print("all review assertions passed")
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()

