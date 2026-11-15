#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of cpe package.

This module allows to store the value of the logical components
of a CPE name and compare it with others.

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

from .cpecomp import CPEComponent


class CPEComponentLogical(CPEComponent):
    """
    Represents a generic logical component of CPE name, compatible with
    the components of all versions of CPE specification.

    The logical values form a small, closed type system that is kept
    strictly separate from ordinary string values:

    - ANY: matches every value except NA.
    - NA: matches only NA.
    - UNDEFINED: matches every value except NA (unconstrained).
    - EMPTY: matches every value except NA (legacy empty component).

    Equality truth table (strict, no cross-state equality):

    - ANY == ANY, NA == NA, UNDEFINED == UNDEFINED, EMPTY == EMPTY.
    - Any other combination is not equal.

    Containment truth table ("in" operator):

    - ANY contains every value (including NA).
    - NA contains only NA.
    - UNDEFINED contains every value (including NA).
    - EMPTY contains every value (including NA).

    Set operations truth table:

    - intersection: NA ∩ x = NA, ANY ∩ x = x, UNDEFINED ∩ x = x,
      EMPTY ∩ x = x, x ∩ x = x.
    - union: ANY ∪ x = ANY, NA ∪ x = x, UNDEFINED ∪ EMPTY = ANY,
      x ∪ x = x.
    - difference: x - ANY = NA, NA - x = NA, x - x = NA, otherwise x.

    Serialization truth table (WFN syntax):

    - ANY → ANY, NA → NA, UNDEFINED → ANY, EMPTY → ANY.

    Legacy compatibility truth table (used when comparing CPE names
    across versions, e.g. 1.1 vs 2.3):

    - NA is only compatible with NA.
    - ANY, UNDEFINED and EMPTY are mutually compatible.
    """

    ###############
    #  CONSTANTS  #
    ###############

    # Logical values in integer format

    #: Value of an undefined component. For example, edition attribute in the
    #: CPE name cpe:/cisco::2345 of version 1.1 of CPE specification
    _VALUE_INT_UNDEFINED = -1

    #: Value of an empty component. For example, product attribute in the
    #: CPE name cpe:/cisco::2345 of version 1.1 of CPE specification
    _VALUE_INT_EMPTY = 0

    #: Value of a component "any value". For example, product attribute in the
    #: CPE name cpe:/h:cisco:*:2345 of version 2.3 of CPE specification
    _VALUE_INT_ANY = 1

    #: Value of a not applicable component. For example, product attribute in
    #: the CPE name cpe:/h:cisco:-:2345 of version 2.3 of CPE specification
    _VALUE_INT_NA = 2

    ####################
    #  OBJECT METHODS  #
    ####################

    def __contains__(self, item):
        """
        Returns True if item is included in set of values of self.

        :param CPEComponent item: component to find in self
        :returns: True if item is included in set of self
        :rtype: boolean
        """

        return True

    def __eq__(self, other):
        """
        Returns True if other (first element of operation) and
        self (second element of operation) are equal components,
        false otherwise.

        :param CPEComponent other: component to compare
        :returns: True if other == self, False otherwise
        :rtype: boolean
        :exception: NotImplementedError - class method not implemented
        """

        errmsg = "Class method not implemented. Use the method of some child class"
        raise NotImplementedError(errmsg)

    def __str__(self):
        """
        Returns a human-readable representation of CPE component.

        :returns: Representation of CPE component as string
        :rtype: string
        :exception: NotImplementedError - class method not implemented
        """

        errmsg = "Class method not implemented. Use the method of some child class"
        raise NotImplementedError(errmsg)

    def matches(self, other):
        """
        Returns True if the logical value of self matches the logical
        value of other, according to the matching truth table:

        - ANY matches every value.
        - NA matches only NA.
        - UNDEFINED matches every value.
        - EMPTY matches every value.

        :param CPEComponent other: component to match
        :returns: True if other is matched by self, False otherwise
        :rtype: boolean
        """

        return other in self

    def intersection(self, other):
        """
        Returns the intersection of self and other, according to
        the set-operation truth table.

        :param CPEComponent other: component to intersect
        :returns: Intersection component
        :rtype: CPEComponentLogical
        """

        from .cpecomp_notapplicable import CPEComponentNotApplicable
        from .cpecomp_anyvalue import CPEComponentAnyValue

        if isinstance(self, CPEComponentNotApplicable) or \
           isinstance(other, CPEComponentNotApplicable):
            return CPEComponentNotApplicable()

        if isinstance(self, CPEComponentAnyValue):
            return other

        if isinstance(other, CPEComponentAnyValue):
            return self

        if type(self) is type(other):
            return self

        # UNDEFINED ∩ EMPTY: both unconstrained, result is unconstrained
        from .cpecomp_undefined import CPEComponentUndefined
        return CPEComponentUndefined()

    def union(self, other):
        """
        Returns the union of self and other, according to
        the set-operation truth table.

        :param CPEComponent other: component to unite
        :returns: Union component
        :rtype: CPEComponentLogical
        """

        from .cpecomp_anyvalue import CPEComponentAnyValue
        from .cpecomp_notapplicable import CPEComponentNotApplicable

        if isinstance(self, CPEComponentAnyValue) or \
           isinstance(other, CPEComponentAnyValue):
            return CPEComponentAnyValue()

        if isinstance(self, CPEComponentNotApplicable):
            return other

        if isinstance(other, CPEComponentNotApplicable):
            return self

        if type(self) is type(other):
            return self

        # UNDEFINED ∪ EMPTY: both unconstrained, result is unconstrained
        return CPEComponentAnyValue()

    def difference(self, other):
        """
        Returns the difference of self and other, according to
        the set-operation truth table.

        :param CPEComponent other: component to subtract
        :returns: Difference component
        :rtype: CPEComponentLogical
        """

        from .cpecomp_notapplicable import CPEComponentNotApplicable
        from .cpecomp_anyvalue import CPEComponentAnyValue

        # NA - x = NA
        if isinstance(self, CPEComponentNotApplicable):
            return self

        # x - ANY = NA
        if isinstance(other, CPEComponentAnyValue):
            return CPEComponentNotApplicable()

        # x - x = NA
        if type(self) is type(other):
            return CPEComponentNotApplicable()

        # otherwise self
        return self

    def is_compatible_with(self, other):
        """
        Returns True if self and other are compatible logical values
        across versions of CPE specification, according to the legacy
        compatibility truth table.

        :param CPEComponent other: component to check
        :returns: True if compatible, False otherwise
        :rtype: boolean
        """

        from .cpecomp_notapplicable import CPEComponentNotApplicable

        # NA only compatible with NA
        if isinstance(self, CPEComponentNotApplicable) or \
           isinstance(other, CPEComponentNotApplicable):
            return (isinstance(self, CPEComponentNotApplicable) and
                    isinstance(other, CPEComponentNotApplicable))

        # ANY, UNDEFINED and EMPTY are mutually compatible
        return True

    def as_wfn(self):
        """
        Returns the value of component encoded as Well-Formed Name (WFN)
         string, according to the serialization truth table.

         :returns: WFN string associated with component
         :rtype: string
         """

        from .cpecomp2_3_wfn import CPEComponent2_3_WFN
        from .cpecomp_notapplicable import CPEComponentNotApplicable

        if isinstance(self, CPEComponentNotApplicable):
            return CPEComponent2_3_WFN.VALUE_NA

        return CPEComponent2_3_WFN.VALUE_ANY

if __name__ == "__main__":
    import doctest
    doctest.testmod()
    doctest.testfile('../tests/testfile_cpecomp_logical.txt')
