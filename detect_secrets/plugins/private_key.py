"""
This code was extracted in part from
https://github.com/pre-commit/pre-commit-hooks. Using similar heuristic logic,
we adapted it to fit our plugin infrastructure, to create an organized,
concerted effort in detecting all type of secrets in code.

Copyright (c) 2014 pre-commit dev team: Anthony Sottile, Ken Struys

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import re

from ..core.potential_secret import PotentialSecret
from .base import MultiLinePlugin
from .base import RegexBasedDetector


class PrivateKeyDetector(MultiLinePlugin, RegexBasedDetector):
    """
    Scans for private keys.

    This checks for private keys by determining whether the denylisted
    lines are present in the analyzed string.

    When scanning files, whole PEM blocks (including the BEGIN/END
    markers) are captured as a single secret spanning multiple lines,
    so the entire credential is reported with accurate start and end
    line numbers. Lone header markers (e.g. unterminated blocks, or
    formats without a closing marker) are still reported on their own,
    preserving the historical fingerprints for those cases.
    """

    secret_type = 'Private Key'

    denylist = [
        re.compile(regexp)
        for regexp in (
            r'BEGIN DSA PRIVATE KEY',
            r'BEGIN EC PRIVATE KEY',
            r'BEGIN OPENSSH PRIVATE KEY',
            r'BEGIN PGP PRIVATE KEY BLOCK',
            r'BEGIN PRIVATE KEY',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN SSH2 ENCRYPTED PRIVATE KEY',
            r'PuTTY-User-Key-File-2',
        )
    ]

    # Matches a complete PEM block, from the BEGIN marker to its matching
    # END marker. The captured group is the key type (e.g. "RSA PRIVATE
    # KEY"), and is backreferenced to pair the markers correctly.
    block_denylist = [
        re.compile(
            r'-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----'
            r'.*?'
            r'-----END \1-----',
            re.DOTALL,
        ),
    ]

    def analyze_multiline(self, filename, lines, line_number=1, **kwargs):
        text = '\n'.join(lines)

        output = set()
        block_spans = []
        for regex in self.block_denylist:
            for match in regex.finditer(text):
                block_spans.append(match.span())
                output.add(
                    PotentialSecret(
                        type=self.secret_type,
                        filename=filename,
                        secret=match.group(0),
                        line_number=line_number + text.count('\n', 0, match.start()),
                        end_line_number=line_number + text.count('\n', 0, match.end()),
                    ),
                )

        # Fall back to lone header markers, so that unterminated blocks
        # (or formats without a closing marker) are still flagged, with
        # the same fingerprint that single-line scanning produced.
        for regex in self.denylist:
            for match in regex.finditer(text):
                if any(
                    start <= match.start() < end
                    for start, end in block_spans
                ):
                    continue

                output.add(
                    PotentialSecret(
                        type=self.secret_type,
                        filename=filename,
                        secret=match.group(0),
                        line_number=line_number + text.count('\n', 0, match.start()),
                    ),
                )

        return output
