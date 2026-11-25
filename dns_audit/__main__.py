"""支持 ``python -m dns_audit`` 调用 CLI。"""
from .cli import main

if __name__ == '__main__':
    raise SystemExit(main())
