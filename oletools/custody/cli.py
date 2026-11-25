"""Command line interface for progressive custody inspections.

Examples:
    # first sampling: structure only, produces the seal inventory
    python -m oletools.custody.cli seal sample.docx --manifest m.json

    # grant an approval for one observed object
    python -m oletools.custody.cli approve m.json zip-5

    # progressive pass: release only still-approved objects
    python -m oletools.custody.cli inspect sample.docx \
        --manifest m.json --release zip-5 --out-dir released/
"""

import argparse
import json
import os
import sys

from oletools.custody.backend import Backend
from oletools.custody.manifest import CustodyManifest


def build_parser():
    parser = argparse.ArgumentParser(
        description='Progressive custody inspection backend')
    sub = parser.add_subparsers(dest='command')

    seal = sub.add_parser('seal', help='structure-only first sampling')
    seal.add_argument('path')
    seal.add_argument('--manifest', required=True)

    approve = sub.add_parser('approve', help='record an object approval')
    approve.add_argument('manifest')
    approve.add_argument('object_id')
    approve.add_argument('--approval-id', default=None)

    inspect = sub.add_parser(
        'inspect', help='progressive manifest-driven pass')
    inspect.add_argument('path')
    inspect.add_argument('--manifest', required=True)
    inspect.add_argument('--release', nargs='*', default=[])
    inspect.add_argument('--out-dir', default=None)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    backend = Backend()
    if args.command == 'seal':
        manifest, observation = backend.create_manifest(args.path)
        manifest.save(args.manifest)
        print('sealed {0} objects into {1}'.format(
            len(observation.objects), args.manifest))
        for obj in observation.objects:
            print('  {0:10s} {1}'.format(obj.object_id, obj.name))
        return 0

    if args.command == 'approve':
        manifest = CustodyManifest.load(args.manifest)
        approval = backend.grant_approval(
            manifest, args.object_id, approval_id=args.approval_id)
        manifest.save(args.manifest)
        print('granted {0} for {1}'.format(
            approval.approval_id, args.object_id))
        return 0

    if args.command == 'inspect':
        manifest = CustodyManifest.load(args.manifest)
        result = backend.inspect(
            args.path, manifest, release_ids=args.release)
        if args.out_dir and result.released_objects:
            os.makedirs(args.out_dir, exist_ok=True)
            for item in result.released_objects:
                target = os.path.join(
                    args.out_dir, item.observation.object_id + '.bin')
                with open(target, 'wb') as handle:
                    handle.write(item.data)
        print(json.dumps({
            'released': result.released,
            'revoked': result.revoked,
            'denied': result.denied,
            'observable': [obj.object_id for obj in
                           result.objects_still_observable()],
        }, indent=2, sort_keys=True))
        manifest.save(args.manifest)
        return 0

    build_parser().print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
