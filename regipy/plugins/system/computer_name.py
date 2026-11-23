import logging

from regipy.exceptions import RegistryValueNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

COMPUTER_NAME_PATH = r"Control\ComputerName\ComputerName"


class ComputerNamePlugin(Plugin):
    NAME: str = "computer_name"
    DESCRIPTION = "Get the computer name"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started Computer Name Plugin...")

        for subkey_path in self.registry_hive.get_control_sets(COMPUTER_NAME_PATH):
            with self.evidence_scope() as scope:
                subkey = self.registry_hive.get_key(subkey_path)
                self.evidence_key_read(subkey_path)
                try:
                    computer_name = subkey.get_value("ComputerName", as_json=self.as_json)
                    self.evidence_value_read(subkey_path, "ComputerName")
                except RegistryValueNotFoundException:
                    # The missing value participates in the conclusion.
                    self.evidence_value_missing(subkey_path, "ComputerName")
                    logger.exception("Could not get computer name")
                    continue
            self.entries.append(
                {
                    "name": computer_name,
                    "timestamp": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                }
            )
            self.bind_evidence(len(self.entries) - 1, scope)
