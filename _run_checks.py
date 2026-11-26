import pathlib
import sys
import tempfile
import traceback

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import test_direction_audit as tests


def main():
    failures = []
    passed = 0
    for name in sorted(dir(tests)):
        if not name.startswith("test_"):
            continue
        fn = getattr(tests, name)
        if not callable(fn):
            continue
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="da-check-"))
        try:
            if "tmp_path" in fn.__code__.co_varnames:
                fn(tmp)
            else:
                fn()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
            failures.append(name)
    print(f"\n{passed} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
