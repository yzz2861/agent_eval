# Compatibility wrapper for the truststore planning CLI.
from __future__ import absolute_import

try:
    from .plan_truststores import *  # noqa: F401,F403
    from .plan_truststores import main, build_plan_from_config  # noqa: F401
except (ImportError, SystemError, ValueError):
    from plan_truststores import *  # noqa: F401,F403
    from plan_truststores import main, build_plan_from_config  # noqa: F401

if __name__ == '__main__':
    import sys
    sys.exit(main())
