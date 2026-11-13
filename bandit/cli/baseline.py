#
# Copyright 2015 Hewlett-Packard Enterprise
#
# SPDX-License-Identifier: Apache-2.0
# #############################################################################
# Bandit Baseline is a tool that runs Bandit against a Git commit, and compares
# the current commit findings to the parent commit findings.
# To do this it checks out the parent commit, runs Bandit (with any provided
# filters or profiles), checks out the current commit, runs Bandit, and then
# reports on any new findings.
# #############################################################################
"""Bandit is a tool designed to find common security issues in Python code."""
import argparse
import contextlib
import logging
import os
import shutil
import subprocess  # nosec: B404
import sys
import tempfile

from bandit.core import manager as b_manager

try:
    import git
except ImportError:
    git = None

bandit_args = sys.argv[1:]
baseline_tmp_file = "_bandit_baseline_run.json_"
current_commit = None
default_output_format = "terminal"
LOG = logging.getLogger(__name__)
repo = None
report_basename = "bandit_baseline_result"
valid_baseline_formats = ["txt", "html", "json"]

"""baseline.py"""


def main():
    """Execute Bandit."""
    # our cleanup function needs this and can't be passed arguments
    global current_commit
    global repo

    parent_commit = None
    output_format = None
    repo = None
    report_fname = None

    init_logger()

    # explicit migration of a legacy baseline report, then exit
    migrate_target = _migrate_baseline_target()
    if migrate_target is not None:
        sys.exit(0 if migrate_baseline_file(migrate_target) else 2)

    output_format, repo, report_fname = initialize()

    if not repo:
        sys.exit(2)

    # #################### Find current and parent commits ####################
    try:
        commit = repo.commit()
        current_commit = commit.hexsha
        LOG.info("Got current commit: [%s]", commit.name_rev)

        commit = commit.parents[0]
        parent_commit = commit.hexsha
        LOG.info("Got parent commit: [%s]", commit.name_rev)

    except git.GitCommandError:
        LOG.error("Unable to get current or parent commit")
        sys.exit(2)
    except IndexError:
        LOG.error("Parent commit not available")
        sys.exit(2)

    # #################### Run Bandit against both commits ####################
    output_type = (
        ["-f", "txt"]
        if output_format == default_output_format
        else ["-o", report_fname]
    )

    with baseline_setup() as t:
        bandit_tmpfile = f"{t}/{baseline_tmp_file}"

        steps = [
            {
                "message": "Getting Bandit baseline results",
                "commit": parent_commit,
                "args": bandit_args + ["-f", "json", "-o", bandit_tmpfile],
            },
            {
                "message": "Comparing Bandit results to baseline",
                "commit": current_commit,
                "args": bandit_args + ["-b", bandit_tmpfile] + output_type,
            },
        ]

        return_code = None

        for step in steps:
            repo.head.reset(commit=step["commit"], working_tree=True)

            LOG.info(step["message"])

            bandit_command = ["bandit"] + step["args"]

            try:
                output = subprocess.check_output(bandit_command)  # nosec: B603
            except subprocess.CalledProcessError as e:
                output = e.output
                return_code = e.returncode
            else:
                return_code = 0
                output = output.decode("utf-8")  # subprocess returns bytes

            if return_code not in [0, 1]:
                LOG.error(
                    "Error running command: %s\nOutput: %s\n",
                    bandit_args,
                    output,
                )

    # #################### Output and exit ####################################
    # print output or display message about written report
    if output_format == default_output_format:
        print(output)
    else:
        LOG.info("Successfully wrote %s", report_fname)

    # exit with the code the last Bandit run returned
    sys.exit(return_code)


# #################### Migrate legacy baseline reports ########################
def _migrate_baseline_target():
    """Return the --migrate-baseline argument value, if provided."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--migrate-baseline",
        metavar="BASELINE_REPORT",
        default=None,
        help="migrate a legacy baseline report to stable fingerprints "
        "and exit",
    )
    args, _ = parser.parse_known_args(bandit_args)
    return args.migrate_baseline


def migrate_baseline_file(path):
    """Migrate a legacy baseline report to stable fingerprints.

    Rewrites the report in place, adding a fingerprint to every issue
    that can be migrated from its stored code snippet. Issues that
    cannot be migrated keep legacy equality matching, they are never
    blindly treated as already existing.

    :param path: Path to the baseline report to migrate
    :return: True if the report was migrated and written successfully
    """
    try:
        with open(path) as fd:
            data = fd.read()
    except OSError as e:
        LOG.error("Unable to read baseline report %s: %s", path, e)
        return False

    try:
        data, migrated, failed = b_manager.migrate_baseline_data(data)
    except ValueError as e:
        LOG.error("Unable to parse baseline report %s: %s", path, e)
        return False

    try:
        with open(path, "w") as fd:
            fd.write(data)
    except OSError as e:
        LOG.error("Unable to write baseline report %s: %s", path, e)
        return False

    LOG.info(
        "Migrated %d issue(s) to stable fingerprints, %d issue(s) "
        "could not be migrated",
        migrated,
        failed,
    )
    return True


# #################### Clean up before exit ###################################
@contextlib.contextmanager
def baseline_setup():
    """Baseline setup by creating temp folder and resetting repo."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, True)

    if repo:
        repo.head.reset(commit=current_commit, working_tree=True)


# #################### Setup logging ##########################################
def init_logger():
    """Init logger."""
    LOG.handlers = []
    log_level = logging.INFO
    log_format_string = "[%(levelname)7s ] %(message)s"
    logging.captureWarnings(True)
    LOG.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(log_format_string))
    LOG.addHandler(handler)


# #################### Perform initialization and validate assumptions ########
def initialize():
    """Initialize arguments and output formats."""
    valid = True

    # #################### Parse Args #########################################
    parser = argparse.ArgumentParser(
        description="Bandit Baseline - Generates Bandit results compared to "
        "a baseline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Additional Bandit arguments such as severity filtering (-ll) "
        "can be added and will be passed to Bandit.",
    )
    if sys.version_info >= (3, 14):
        parser.suggest_on_error = True
        parser.color = False

    parser.add_argument(
        "targets",
        metavar="targets",
        type=str,
        nargs="+",
        help="source file(s) or directory(s) to be tested",
    )

    parser.add_argument(
        "-f",
        dest="output_format",
        action="store",
        default="terminal",
        help="specify output format",
        choices=valid_baseline_formats,
    )

    parser.add_argument(
        "--migrate-baseline",
        metavar="BASELINE_REPORT",
        default=None,
        help="migrate a legacy baseline report to stable fingerprints "
        "and exit",
    )

    args, _ = parser.parse_known_args()

    # #################### Setup Output #######################################
    # set the output format, or use a default if not provided
    output_format = (
        args.output_format if args.output_format else default_output_format
    )

    if output_format == default_output_format:
        LOG.info("No output format specified, using %s", default_output_format)

    # set the report name based on the output format
    report_fname = f"{report_basename}.{output_format}"

    # #################### Check Requirements #################################
    if git is None:
        LOG.error("Git not available, reinstall with baseline extra")
        valid = False
        return (None, None, None)

    try:
        repo = git.Repo(os.getcwd())

    except git.exc.InvalidGitRepositoryError:
        LOG.error("Bandit baseline must be called from a git project root")
        valid = False

    except git.exc.GitCommandNotFound:
        LOG.error("Git command not found")
        valid = False

    else:
        if repo.is_dirty():
            LOG.error(
                "Current working directory is dirty and must be " "resolved"
            )
            valid = False

    # if output format is specified, we need to be able to write the report
    if output_format != default_output_format and os.path.exists(report_fname):
        LOG.error("File %s already exists, aborting", report_fname)
        valid = False

    # Bandit needs to be able to create this temp file
    if os.path.exists(baseline_tmp_file):
        LOG.error(
            "Temporary file %s needs to be removed prior to running",
            baseline_tmp_file,
        )
        valid = False

    # we must validate -o is not provided, as it will mess up Bandit baseline
    if "-o" in bandit_args:
        LOG.error("Bandit baseline must not be called with the -o option")
        valid = False

    return (output_format, repo, report_fname) if valid else (None, None, None)


if __name__ == "__main__":
    main()
