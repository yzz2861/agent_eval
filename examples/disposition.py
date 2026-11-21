#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

from filetype.disposition import (
    Consumer,
    DispositionPolicy,
    PublicationQueue,
    QuarantineArbiter,
)


def main():
    policy = DispositionPolicy()
    policy.require(
        "application/zip", "archive.shell", "archive.contents")

    queue = PublicationQueue()
    arbiter = QuarantineArbiter(policy, queue)
    published = []
    arbiter.subscribe(published.append)

    arbiter.admit_file(
        "upload-1", "tests/fixtures/sample.zip",
        content_id="sha256:fixture-zip")

    vendor = Consumer(
        "external-indexer", ["archive.shell"], external=True)
    first = arbiter.acknowledge(
        "upload-1", vendor, ["archive.shell"],
        confirmation_id="receipt-shell",
        content_id="sha256:fixture-zip")
    print("after shell: status=%s missing=%s publications=%d" % (
        arbiter.decision("upload-1").status,
        sorted(first.missing), len(queue)))

    handler = Consumer(
        "fake-handler", ["archive.shell", "archive.contents"])
    second = arbiter.acknowledge(
        "upload-1", handler, ["archive.contents"],
        confirmation_id="receipt-contents",
        content_id="sha256:fixture-zip")
    print("after contents: released=%s notifications=%d queue=%d" % (
        second.released, len(published), len(queue)))
    print("released by: %s" % (published[0].released_by,))


if __name__ == "__main__":
    main()
