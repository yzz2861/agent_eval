#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import datetime

from .helpers import bad_module_attribute_use
from . import hashlib_exemptions


class BadHashlibUseLinter(bad_module_attribute_use.BadModuleAttributeUseLinter):
    """This linter looks for unsafe use of the Python "hashlib" module. Use of
    md5|sha1 is known to have hash collision weaknesses.
    """
    off_by_default = False

    _code = 'DUO130'
    _error_tmpl = 'DUO130 insecure use of "hashlib" module'

    @property
    def illegal_module_attributes(self):
        return {
            'hashlib': [
                'md5',
                'sha1',
            ],
        }

    def __init__(self, filename=None, today=None, *args, **kwargs):
        self.filename = filename
        self.today = today or datetime.date.today()
        self._module_node = None

        super(BadHashlibUseLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        self._module_node = node
        self.generic_visit(node)

    def get_results(self):
        results = super(BadHashlibUseLinter, self).get_results()
        if self._module_node is None:
            return results

        return hashlib_exemptions.filter_results(
            results,
            self._module_node,
            self.filename,
            self.today
        )
