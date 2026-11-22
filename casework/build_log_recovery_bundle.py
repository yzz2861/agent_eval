"""Build the transaction-log recovery demonstration bundle.

This keeps the large SYSTEM hive (and its LOG1/LOG2 copies) separate from the
compact excerpt bundle, so each run produces a readable two-level directory.
"""

import os
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(REPO_ROOT, 'casework', 'log_recovery_bundle')


def main():
    if os.path.exists(BUNDLE):
        shutil.rmtree(BUNDLE)
    target = os.path.join(BUNDLE, 'log_copies', 'new_log_1')
    os.makedirs(target)
    source = os.path.join(REPO_ROOT, 'testing', 'reg_samples', 'new_log_1')
    for name in ('SYSTEM', 'SYSTEM.LOG1', 'SYSTEM.LOG2'):
        shutil.copy(os.path.join(source, name), os.path.join(target, name))
    print('Log recovery bundle written to %s' % BUNDLE)


if __name__ == '__main__':
    main()
