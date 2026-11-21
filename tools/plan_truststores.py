#!/usr/bin/env python
# vim: set et ai ts=4 sts=4 sw=4:
# Command line wrapper for purpose-scoped truststore planning.

from __future__ import print_function

import argparse
import json
import os
import sys

import jks
from jks.truststore import TruststorePlanner


def load_config(path):
    with open(path, 'rb') as handle:
        return json.loads(handle.read().decode('utf-8'))


def planner_from_config(config):
    intake = config.get('intake') or config.get('store') or config.get('keystore')
    if intake is None:
        intake = {
            'path': config.get('path'),
            'password': config.get('password'),
            'name': config.get('name'),
            'type': config.get('type'),
        }
    declarations = (config.get('declarations') or config.get('approvals') or
                    config.get('entries'))
    purposes = config.get('purposes') or config.get('approved_purposes')
    return TruststorePlanner(intake, declarations, purposes)


def build_plan_from_config(config):
    return planner_from_config(config).build()


def write_truststores(planner, plan, directory, password=None):
    if not os.path.isdir(directory):
        os.makedirs(directory)
    written = {}
    for purpose, manifest in plan.manifests.items():
        path = os.path.join(directory, str(purpose) + '.jks')
        manifest.to_keystore().save(path, password or '')
        written[str(purpose)] = path
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Plan minimal purpose-scoped Java truststores.')
    parser.add_argument('config', help='Path to the JSON planning configuration.')
    parser.add_argument('--output', help='Write the delivery plan JSON to this path.')
    parser.add_argument('--truststore-dir',
                        help='Optionally materialize the planned JKS truststores.')
    parser.add_argument('--truststore-password',
                        help='Password for materialized truststores.')
    args = parser.parse_args(argv)

    config = load_config(args.config)
    planner = planner_from_config(config)
    plan = planner.build()
    text = plan.to_json()
    if args.output:
        with open(args.output, 'wb') as handle:
            handle.write(text.encode('utf-8'))
    else:
        print(text)

    if args.truststore_dir:
        written = write_truststores(planner, plan, args.truststore_dir,
                                    args.truststore_password)
        for purpose, path in sorted(written.items()):
            print('wrote %s truststore: %s' % (purpose, path), file=sys.stderr)

    verification = plan.verify(planner.store)
    if not verification.ok:
        for problem in verification.problems:
            print('verification: %s' % problem, file=sys.stderr)
        return 1
    if not plan.ok:
        for conflict in plan.errors:
            print('conflict: %s' % conflict, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
