#!/usr/bin/env python
"""Print the shared-certificate trust-impact example."""

from __future__ import print_function

import jks


def main():
    preview, facts = jks.shared_certificate_example()
    print(preview.format())
    print()
    print("expanded_application:", facts["expanded_application"])
    print("transition:", facts["transition"])
    print("duplicate_aliases:", facts["duplicate_aliases"])
    print("added_certificate_fingerprints:", facts["added_certificate_fingerprints"])


if __name__ == "__main__":
    main()
