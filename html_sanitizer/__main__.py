import sys

from .preview import main as preview_main
from .sanitizer import Sanitizer


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    preview_flags = {
        "--preview",
        "--old",
        "--old-config",
        "--new",
        "--new-config",
        "--format",
        "--include-unchanged",
        "--debug",
    }
    if any(
        argument in preview_flags
        or argument.startswith(("--old=", "--new=", "--format="))
        for argument in argv
    ):
        if "--preview" in argv:
            argv.remove("--preview")
        return preview_main(argv)

    sanitizer = Sanitizer()
    if argv:
        for filename in argv:
            with open(filename) as f:
                print(sanitizer.sanitize(f.read()))
    else:
        print(sanitizer.sanitize(sys.stdin.read()).encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
