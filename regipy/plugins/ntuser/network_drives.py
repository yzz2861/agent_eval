import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

NETWORK_DRIVES = r"\Network"


class NetworkDrivesPlugin(Plugin):
    NAME = "network_drives_plugin"
    DESCRIPTION = "Parse the user's mapped network drives"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            network_drives = self.registry_hive.get_key(NETWORK_DRIVES)
        except RegistryKeyNotFoundException as ex:
            # No mapped drives conclusion rests on the absence of \Network.
            self.evidence_key_missing(NETWORK_DRIVES)
            logger.error(f"Could not find {self.NAME} plugin data at: {NETWORK_DRIVES}: {ex}")
            return

        self.evidence_key_read(NETWORK_DRIVES)
        for mapped_drive in network_drives.iter_subkeys():
            drive_path = rf"{NETWORK_DRIVES}\{mapped_drive.name}"
            with self.evidence_scope() as scope:
                self.evidence_key_read(drive_path)
                timestamp = convert_wintime(mapped_drive.header.last_modified, as_json=self.as_json)
                remote_path = mapped_drive.get_value("RemotePath")
                if remote_path is None:
                    self.evidence_value_missing(drive_path, "RemotePath")
                else:
                    self.evidence_value_read(drive_path, "RemotePath")
            self.entries.append(  # type: ignore[union-attr]
                {
                    "last_write": timestamp,
                    "drive_letter": mapped_drive.name,
                    "network_path": remote_path,
                }
            )
            self.bind_evidence(len(self.entries) - 1, scope)
