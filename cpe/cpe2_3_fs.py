#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of cpe package.

This module is used to the treatment of identifiers
of IT platforms (hardware, operating systems or applications of system)
in accordance with binding style formatted string of version 2.3 of CPE
(Common Platform Enumeration) specification.

Copyright (C) 2013  Alejandro Galindo García, Roberto Abdelkader Martínez Pérez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

For any problems using the cpe package, or general questions and
feedback about it, please contact:

- Alejandro Galindo García: galindo.garcia.alejandro@gmail.com
- Roberto Abdelkader Martínez Pérez: robertomartinezp@gmail.com
"""

from .cpe import CPE
from .cpe2_3 import CPE2_3
from .comp.cpecomp import CPEComponent
from .comp.cpecomp_logical import CPEComponentLogical
from .comp.cpecomp2_3_fs import CPEComponent2_3_FS
from .comp.cpecomp_anyvalue import CPEComponentAnyValue
from .comp.cpecomp_notapplicable import CPEComponentNotApplicable


class CPE2_3_FS(CPE2_3):
    """
    Implementation of binding style formatted string of version 2.3
    of CPE specification.

    Each name starts with the prefix 'cpe:2.3:'.

    Each platform can be broken down into many distinct parts.
    A CPE Name specifies a simple part and is used to identify
    any platform that matches the description of that part.

    The distinct parts are:

    - Hardware part: the physical platform supporting the IT system.
    - Operating system part: the operating system controls and manages the
      IT hardware.
    - Application part: software systems, services, servers, and packages
      installed on the system.

    CPE Name syntax:

        cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """

    ###############
    #  CONSTANTS  #
    ###############

    #: Style of CPE Name
    STYLE = CPE2_3.STYLE_FS

    #: Prefix of CPE Name with formatted string style
    _PREFIX = "cpe:2.3:"

    #: Number of components of a CPE Name with formatted string style
    COMPONENT_COUNT = 11

    #: Maximum length in characters of a single component value.
    #: Longer fields are rejected before any component object is built.
    MAX_FIELD_LENGTH = 1024

    #: Maximum depth of consecutive escape characters accepted
    #: in a component value
    MAX_ESCAPE_DEPTH = 32

    #: Maximum characters of a component value included in error messages
    _MAX_VALUE_SHOWN = 64

    ###############
    #  VARIABLES  #
    ###############

    #: Accepted values of the part component of CPE Name
    _PART_VALUES = (CPEComponent.VALUE_PART_HW,
                    CPEComponent.VALUE_PART_OS,
                    CPEComponent.VALUE_PART_APP,
                    CPEComponent2_3_FS.VALUE_ANY,
                    CPEComponent2_3_FS.VALUE_NA)

    ###################
    #  CLASS METHODS  #
    ###################

    @classmethod
    def _check_field_length(cls, text, start, end, offset):
        """
        Checks the length of the component value text[start:end]
        against the field length budget.

        :param string text: CPE Name body being partitioned
        :param int start: start index of the component value in text
        :param int end: end index of the component value in text
        :param int offset: position of text in the original CPE Name
        :returns: None
        :exception: ValueError - component value exceeds the maximum
            field length
        """

        if end - start > cls.MAX_FIELD_LENGTH:
            errmsg = ("Bad-formed CPE Name: component at position {0} "
                      "exceeds maximum length {1}").format(
                          offset + start, cls.MAX_FIELD_LENGTH)
            raise ValueError(errmsg)

    @classmethod
    def _split_components(cls, text, offset=0):
        """
        Splits the body of a CPE Name into its component values.
        Component separators are colons not immediately preceded by
        an escape character. The scan is a single linear pass and
        enforces the component count, field length and escape depth
        budgets, failing before any large object is allocated.

        :param string text: CPE Name body (without the 'cpe:2.3:' prefix)
        :param int offset: position of text in the original CPE Name,
            used to report stable positions in errors
        :returns: component values found, in order
        :rtype: list
        :exception: ValueError - budget exceeded or unterminated escape
        """

        separator = CPEComponent2_3_FS.SEPARATOR_COMP
        escape = "\\"

        fields = []
        field_start = 0
        idx = 0
        length = len(text)

        while idx < length:
            c = text[idx]

            if c == escape:
                # Measure the run of consecutive escape characters
                run_start = idx
                while idx < length and text[idx] == escape:
                    idx += 1

                depth = idx - run_start
                if depth > cls.MAX_ESCAPE_DEPTH:
                    errmsg = ("Bad-formed CPE Name: escape depth {0} "
                              "exceeds maximum {1} at position {2}").format(
                                  depth, cls.MAX_ESCAPE_DEPTH,
                                  offset + run_start)
                    raise ValueError(errmsg)

                if idx == length and depth % 2 == 1:
                    # Odd escape run at the end of input:
                    # the last escape character quotes nothing
                    errmsg = ("Bad-formed CPE Name: unterminated escape "
                              "at position {0}").format(offset + run_start)
                    raise ValueError(errmsg)

                continue

            if (c == separator and (idx == 0 or text[idx - 1] != escape)):
                # Unescaped separator: close the current component
                if len(fields) >= cls.COMPONENT_COUNT - 1:
                    errmsg = ("Bad-formed CPE Name: too many components, "
                              "separator at position {0} exceeds "
                              "maximum {1}").format(
                                  offset + idx, cls.COMPONENT_COUNT)
                    raise ValueError(errmsg)

                cls._check_field_length(text, field_start, idx, offset)
                fields.append(text[field_start:idx])
                field_start = idx + 1

            idx += 1

        cls._check_field_length(text, field_start, length, offset)
        fields.append(text[field_start:])

        return fields

    @classmethod
    def _truncate(cls, value):
        """
        Truncates a component value so error messages never
        embed a large part of the input string.

        :param string value: component value to truncate
        :returns: value shortened to the maximum displayable length
        :rtype: string
        """

        if len(value) > cls._MAX_VALUE_SHOWN:
            return "{0}...".format(value[:cls._MAX_VALUE_SHOWN])
        return value

    ####################
    #  OBJECT METHODS  #
    ####################

    def __len__(self):
        """
        Returns the number of components of CPE Name. This CPE Name always
        have eleven components set.

        :returns: count of components of CPE Name
        :rtype: int
        """

        return 11

    def __new__(cls, cpe_str, *args, **kwargs):
        """
        Create a new CPE Name of version 2.3 with formatted string style.

        :param string cpe_str: CPE Name string
        :returns: CPE object of version 2.3 of CPE specification with
            formatted string style.
        :rtype: CPE2_3_FS
        """

        return dict.__new__(cls)

    def _parse(self):
        """
        Checks if the CPE Name is valid.

        The formatted string is partitioned in a single linear pass:
        component separators are colons not immediately preceded by
        an escape character. Component count, field length and escape
        depth are bounded, and violations are reported with their
        position in the input string before any component object
        is created.

        :returns: None
        :exception: ValueError - bad-formed CPE Name
        """

        # CPE Name must not have whitespaces
        if (self._str.find(" ") != -1):
            msg = "Bad-formed CPE Name: it must not have whitespaces"
            raise ValueError(msg)

        # A single trailing newline is tolerated for compatibility
        # with the former regular expression based validation
        s = self._str
        if s.endswith("\n"):
            s = s[:-1]

        if not s.startswith(CPE2_3_FS._PREFIX):
            msg = "Bad-formed CPE Name: validation of parts failed"
            raise ValueError(msg)

        # Partitioning of CPE Name in a single linear pass
        offset = len(CPE2_3_FS._PREFIX)
        values = CPE2_3_FS._split_components(s[offset:], offset)

        if len(values) != CPE2_3_FS.COMPONENT_COUNT:
            msg = ("Bad-formed CPE Name: expected {0} components, "
                   "found {1} (end of input at position {2})").format(
                       CPE2_3_FS.COMPONENT_COUNT, len(values),
                       len(self._str))
            raise ValueError(msg)

        part_value = values[0]
        if part_value not in CPE2_3_FS._PART_VALUES:
            msg = "Bad-formed CPE Name: validation of parts failed"
            raise ValueError(msg)

        components = dict()

        for i, ck in enumerate(CPEComponent.CPE_COMP_KEYS_EXTENDED):
            value = values[i]

            if (value == CPEComponent2_3_FS.VALUE_ANY):
                comp = CPEComponentAnyValue()
            elif (value == CPEComponent2_3_FS.VALUE_NA):
                comp = CPEComponentNotApplicable()
            else:
                try:
                    comp = CPEComponent2_3_FS(value, ck)
                except ValueError:
                    errmsg = "Bad-formed CPE Name: not correct value: {0}".format(
                        CPE2_3_FS._truncate(value))
                    raise ValueError(errmsg)

            components[ck] = comp

        # #######################
        #  Storage of CPE Name  #
        # #######################

        part_comp = components[CPEComponent.ATT_PART]
        if isinstance(part_comp, CPEComponentLogical):
            elements = []
            elements.append(components)
            self[CPE.KEY_UNDEFINED] = elements
        else:
            # Create internal structure of CPE Name in parts:
            # one of them is filled with identified components,
            # the rest are empty
            system = part_value
            if system in CPEComponent.SYSTEM_VALUES:
                self._create_cpe_parts(system, components)
            else:
                self._create_cpe_parts(CPEComponent.VALUE_PART_UNDEFINED,
                                       components)

        # Fills the empty parts of internal structure of CPE Name
        for pk in CPE.CPE_PART_KEYS:
            if pk not in self.keys():
                # Empty part
                self[pk] = []

    def get_attribute_values(self, att_name):
        """
        Returns the values of attribute "att_name" of CPE Name.
        By default a only element in each part.

        :param string att_name: Attribute name to get
        :returns: List of attribute values
        :rtype: list
        :exception: ValueError - invalid attribute name
        """

        lc = []

        if not CPEComponent.is_valid_attribute(att_name):
            errmsg = "Invalid attribute name: {0}".format(att_name)
            raise ValueError(errmsg)

        for pk in CPE.CPE_PART_KEYS:
            elements = self.get(pk)
            for elem in elements:
                comp = elem.get(att_name)

                if isinstance(comp, CPEComponentAnyValue):
                    value = CPEComponent2_3_FS.VALUE_ANY

                elif isinstance(comp, CPEComponentNotApplicable):
                    value = CPEComponent2_3_FS.VALUE_NA

                else:
                    value = comp.get_value()

                lc.append(value)
        return lc

if __name__ == "__main__":
    import doctest
    doctest.testmod()
    doctest.testfile("tests/testfile_cpe2_3_fs.txt")
