# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  witness.py

<Purpose>
  Provides a class for inspection witness metadata. A witness is a signed
  attestation, recorded at the original build site, that binds the recorded
  result of an inspection to the exact layout (after parameter substitution),
  the sublayout chain, and the inspection it was created for. It allows a
  verifier to re-check inspection artifact rules offline, i.e. without
  re-executing the inspection command.
"""

import attr
import securesystemslib.formats

from in_toto.formats import _check_hash_dict
from in_toto.models.common import Signable

WITNESS_FILENAME_FORMAT = "{inspection_name}.witness"


@attr.s(repr=False, init=False)
class Witness(Signable):
    """Evidence for an inspection performed at the original build site.

    A Witness object is usually contained in a generic Metablock object for
    signing, serialization and I/O capabilities.

    Attributes:
      name: The name of the inspection in the in-toto layout this witness
          attests to.

      sublayout_chain: A list of step names that identifies the chain of
          sublayout delegations from the root layout to the layout that
          contains the inspection. It is empty for inspections of the root
          layout.

      layout_hash: A hash dictionary over the canonical representation of the
          layout that contains the inspection, after parameter substitution.

      command: A list of command and command arguments of the inspection,
          after parameter substitution.

      materials: A dictionary of the artifacts recorded as materials when the
          inspection was performed at the build site.

      products: A dictionary of the artifacts recorded as products when the
          inspection was performed at the build site.

      byproducts: An opaque dictionary that lists byproducts of the inspection
          command execution. It should have at least the following entries
          "stdout" (str), "stderr" (str) and "return-value" (int).

      environment: An opaque dictionary that lists information about the
          execution environment of the inspection command.

    """

    _type = attr.ib()
    name = attr.ib()
    sublayout_chain = attr.ib()
    layout_hash = attr.ib()
    command = attr.ib()
    materials = attr.ib()
    products = attr.ib()
    byproducts = attr.ib()
    environment = attr.ib()

    def __init__(self, **kwargs):
        super().__init__()

        self._type = "witness"
        self.name = kwargs.get("name")
        self.sublayout_chain = kwargs.get("sublayout_chain", [])
        self.layout_hash = kwargs.get("layout_hash", {})
        self.command = kwargs.get("command", [])
        self.materials = kwargs.get("materials", {})
        self.products = kwargs.get("products", {})
        self.byproducts = kwargs.get("byproducts", {})
        self.environment = kwargs.get("environment", {})

        self.validate()

    @property
    def type_(self):
        """The string "witness" to identify the in-toto metadata type."""
        # NOTE: We expose the type_ property in the API documentation instead of
        # _type to protect it against modification.
        # NOTE: Trailing underscore is used by convention (pep8) to avoid conflict
        # with Python's type keyword.
        return self._type

    @staticmethod
    def read(data):
        """Creates a Witness object from its dictionary representation.

        Arguments:
          data: A dictionary with witness metadata fields.

        Raises:
          securesystemslib.exceptions.FormatError: Passed data is invalid.

        Returns:
          The created Witness object.

        """
        return Witness(**data)

    def _validate_type(self):
        """Private method to check that the _type field is 'witness'."""
        if self._type != "witness":
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field '_type' must be set to 'witness',"
                f" got: {self._type}"
            )

    def _validate_name(self):
        """Private method to check that the name field is a str."""
        if not isinstance(self.name, str):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'name' must be of type str,"
                f" got: {type(self.name)}"
            )

    def _validate_sublayout_chain(self):
        """Private method to check that sublayout_chain is a list of str."""
        if not isinstance(self.sublayout_chain, list) or not all(
            isinstance(name, str) for name in self.sublayout_chain
        ):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'sublayout_chain' must be of type"
                f" list and only contain str, got: {self.sublayout_chain}"
            )

    def _validate_layout_hash(self):
        """Private method to check that layout_hash is a hash dict."""
        _check_hash_dict(self.layout_hash)

    def _validate_command(self):
        """Private method to check that the command field is a list."""
        if not isinstance(self.command, list):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'command' must be of type list,"
                f" got: {type(self.command)}"
            )

    def _validate_materials(self):
        """Private method to check that materials is a dict of hash dicts."""
        if not isinstance(self.materials, dict):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'materials' must be of type dict,"
                f" got: {type(self.materials)}"
            )

        for material in list(self.materials.values()):
            _check_hash_dict(material)

    def _validate_products(self):
        """Private method to check that products is a dict of hash dicts."""
        if not isinstance(self.products, dict):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'products' must be of type dict,"
                f" got: {type(self.products)}"
            )

        for product in list(self.products.values()):
            _check_hash_dict(product)

    def _validate_byproducts(self):
        """Private method to check that the byproducts field is a dict."""
        if not isinstance(self.byproducts, dict):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'byproducts' must be of type dict,"
                f" got: {type(self.byproducts)}"
            )

    def _validate_environment(self):
        """Private method to check that the environment field is a dict."""
        if not isinstance(self.environment, dict):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Witness: field 'environment' must be of type dict,"
                f" got: {type(self.environment)}"
            )
