#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

from sqlparse import tokens as T


class _CaseFilter:
    ttype = None

    def __init__(self, case=None):
        case = case or 'upper'
        self.convert = getattr(str, case)

    def process(self, stream):
        for item in stream:
            ttype, value, source_range = self._unpack(item)
            if ttype in self.ttype:
                converted = self.convert(value)
                if converted != value:
                    source_range = None
                value = converted
            yield self._pack(item, ttype, value, source_range)

    @staticmethod
    def _unpack(item):
        if len(item) == 3:
            return item
        return item[0], item[1], None

    @staticmethod
    def _pack(item, ttype, value, source_range):
        if len(item) == 3:
            return ttype, value, source_range
        return ttype, value


class KeywordCaseFilter(_CaseFilter):
    ttype = T.Keyword


class IdentifierCaseFilter(_CaseFilter):
    ttype = T.Name, T.String.Symbol

    def process(self, stream):
        for item in stream:
            ttype, value, source_range = self._unpack(item)
            if ttype in self.ttype and value.strip()[0] != '"':
                converted = self.convert(value)
                if converted != value:
                    source_range = None
                value = converted
            yield self._pack(item, ttype, value, source_range)


class TruncateStringFilter:
    def __init__(self, width, char):
        self.width = width
        self.char = char

    def process(self, stream):
        for item in stream:
            ttype, value = item[:2]
            source_range = item[2] if len(item) == 3 else None
            if ttype != T.Literal.String.Single:
                yield item
                continue

            if value[:2] == "''":
                inner = value[2:-2]
                quote = "''"
            else:
                inner = value[1:-1]
                quote = "'"

            if len(inner) > self.width:
                value = ''.join((quote, inner[:self.width], self.char, quote))
                source_range = None
            if len(item) == 3:
                yield ttype, value, source_range
            else:
                yield ttype, value
