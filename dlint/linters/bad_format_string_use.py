#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from . import base
from .. import formatstring


class BadFormatStringUseLinter(base.BaseLinter):
    """This linter looks for unsafe use of "str.format" and
    "str.format_map" with format strings that traverse attributes of the
    objects they are given. Attribute chains in replacement fields are
    checked against a capability summary mapping object names to the
    attributes a format string is permitted to access. Format strings
    and object sources that cannot be determined statically are
    reported separately.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 insecure use of "str.format" or "str.format_map"'

    _error_tmpl_unsafe_attribute = (
        'DUO139 format string field "{field}" accesses an attribute '
        'outside the permitted capabilities of "{object_name}"'
    )
    _error_tmpl_unknown_format_string = (
        'DUO139 unable to statically determine the format string'
    )
    _error_tmpl_unknown_object = (
        'DUO139 unable to determine the permitted attributes '
        'of "{object_name}"'
    )

    capabilities = {}

    def __init__(self, capabilities=None, *args, **kwargs):
        if capabilities is not None:
            self.capabilities = capabilities

        super(BadFormatStringUseLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        findings = formatstring.check_module(
            node,
            capabilities=self.capabilities
        )

        for finding in findings:
            self.results.append(
                base.Flake8Result(
                    lineno=finding.lineno,
                    col_offset=finding.col_offset,
                    message=self._message_for(finding)
                )
            )

    def _message_for(self, finding):
        if finding.kind == formatstring.KIND_UNSAFE_ATTRIBUTE:
            return self._error_tmpl_unsafe_attribute.format(
                field=finding.field,
                object_name=finding.object_name
            )

        if finding.kind == formatstring.KIND_UNKNOWN_FORMAT_STRING:
            return self._error_tmpl_unknown_format_string

        if finding.kind == formatstring.KIND_UNKNOWN_OBJECT:
            object_name = finding.object_name
            if object_name is None:
                object_name = '<expression>'

            return self._error_tmpl_unknown_object.format(
                object_name=object_name
            )

        raise ValueError('unexpected finding kind: {}'.format(finding.kind))
