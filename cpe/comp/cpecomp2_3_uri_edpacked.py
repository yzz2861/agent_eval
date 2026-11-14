#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of cpe package.

This module allows to store the value of the packed edition component
of a CPE name of version 2.3 of CPE (Common Platform Enumeration)
specification with Universal Resource Identifier (URI) style.

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

from .cpecomp2_3_uri import CPEComponent2_3_URI


class CPEComponent2_3_URI_edpacked(CPEComponent2_3_URI):
    """
    Represents a packed edition component of version 2.3 of CPE
    specification with URI style.

    A packed edition (for example '~~online~win2003~x64~') is only a view
    used by ``__getitem__``: the five edition sub-components have already
    been parsed and decoded individually when the CPE name was created, so
    this wrapper never decodes percent-encoded sequences again.
    """

    ###############
    #  CONSTANTS  #
    ###############

    #: Separator of components of an edition attribute packed
    SEPARATOR_COMP = "~"

    ####################
    #  OBJECT METHODS  #
    ####################

    def __init__(self, comp_str):
        """
        Store the value of component.

        :param string comp_str: value of component value
        :returns: None
        """

        self._is_negated = False
        self._component_attribute = "edition"
        self._encoded_value = comp_str
        # A packed edition is a presentation-only wrapper over values that
        # were validated and decoded when the parent CPE was parsed; keep the
        # packed string as the standard value instead of decoding it again.
        self._standard_value = comp_str

    def _decode(self):
        """
        The packed edition string is not percent-decoded as a whole;
        its sub-components are decoded independently exactly once.
        """

        return self._encoded_value

    def _is_valid_edition(self):
        """Packed edition structure is validated while parsing the CPE."""

        return self._is_valid_packed_edition(self._encoded_value)

    def _is_valid_value(self):
        """Generic value grammar does not apply to a packed edition."""

        return self._is_valid_packed_edition(self._encoded_value)

    def set_value(self, comp_str, comp_att=None):
        """
        Set the value of component without a second decoding pass.

        :param string comp_str: value of component
        :param string comp_att: attribute associated with the value
        :returns: None
        """

        if not self._is_valid_packed_edition(comp_str):
            msg = "Invalid value of attribute 'edition': {0}".format(comp_str)
            raise ValueError(msg)

        self._is_negated = False
        self._component_attribute = comp_att or "edition"
        self._encoded_value = comp_str
        self._standard_value = comp_str


if __name__ == "__main__":
    import doctest
    doctest.testmod()
