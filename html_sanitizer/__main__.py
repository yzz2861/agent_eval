import argparse
import json
import sys

from .archive import render_review, sanitize_archive
from .sanitizer import Sanitizer


def _read_bytes(path):
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as source:
        return source.read()


def _parser():
    parser = argparse.ArgumentParser(
        prog="python -m html_sanitizer",
        description="Sanitize HTML strings or review strict archive bytes.",
    )
    parser.add_argument("files", nargs="*", help="HTML files to sanitize")
    parser.add_argument(
        "--archive",
        action="store_true",
        help="Treat files as bytes and use the strict archive check.",
    )
    parser.add_argument(
        "--encoding",
        "-e",
        help="Independent encoding declaration for --archive files.",
    )
    parser.add_argument(
        "--source",
        help="Source name stored in archive results and conflicts.",
    )
    parser.add_argument(
        "--archive-pair",
        nargs=2,
        action="append",
        default=[],
        metavar=("ENCODING", "FILE"),
        help="Review one archive with its own encoding; may be repeated.",
    )
    parser.add_argument(
        "--require-metadata",
        action="store_true",
        help="Require BOM or body metadata corroborating each declaration.",
    )
    parser.add_argument(
        "--allow-equivalent-labels",
        action="store_true",
        help="Accept different encoding labels when they decode identically.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print one JSON object per archive result.",
    )
    parser.add_argument(
        "--include-html",
        action="store_true",
        help="Include the sanitized HTML in text review output.",
    )
    return parser


def _print_archive_result(result, args):
    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
    else:
        print(render_review(result, include_html=args.include_html))


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    sanitizer = Sanitizer()

    if args.archive_pair or args.archive:
        if args.archive_pair and args.archive:
            parser.error("choose --archive or --archive-pair")
        if args.archive:
            if not args.encoding:
                parser.error("--archive requires --encoding")
            pairs = [(args.encoding, path) for path in (args.files or ["-"])]
        else:
            if args.files:
                parser.error("positional files cannot be combined with --archive-pair")
            pairs = list(args.archive_pair)
        if not pairs:
            parser.error("no archives to review")

        failed = False
        for encoding, path in pairs:
            result = sanitize_archive(
                _read_bytes(path),
                encoding,
                source=args.source or path,
                sanitizer=sanitizer,
                require_metadata=args.require_metadata,
                strict_labels=not args.allow_equivalent_labels,
                on_conflict="return",
            )
            _print_archive_result(result, args)
            failed = failed or not result.ok
        return 1 if failed else 0

    if args.files:
        for filename in args.files:
            with open(filename) as source:
                print(sanitizer.sanitize(source.read()))
    else:
        print(sanitizer.sanitize(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
