#!/bin/sh
# Local, offline regression runner.
# The sandbox denies stat() on parent directories of the workspace, which breaks
# pytest anchor discovery. Copy the package/tests into a writable temp dir,
# link the in-tree pyelftools and real ELF corpus, then run pytest there.
set -eu

SRC=/Users/bill/领域专项项目/batches/ds-20261120-retry/control/attempts/ds20261120-py28-014/attempt-01/workspace
STAGE="${TMPDIR:-/tmp}/elfharden_regression"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$SRC/elfharden" "$STAGE/"
cp -R "$SRC/tests" "$STAGE/"
cp "$SRC/pytest.ini" "$STAGE/"
ln -s "$SRC/elftools" "$STAGE/elftools"
ln -s "$SRC/test" "$STAGE/test"
cd "$STAGE"
PYTHONPATH="$STAGE" python3 -m pytest tests "$@"
