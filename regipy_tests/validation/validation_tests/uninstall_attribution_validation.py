from regipy.plugins.software.uninstall_attribution import UninstallAttributionPlugin
from regipy_tests.validation.validation import ValidationCase


def test_known_product_is_attributed_to_machine(c: ValidationCase):
    assert any(
        row["subject_kind"] == "machine"
        and row["product_id"] == "{00FC3F65-86EB-475E-881F-A5B1CF731320}"
        and row["state"] == "installed"
        and row["reason"] == "uninstall_registration_observed"
        for row in c.plugin_output
    )


class UninstallAttributionPluginValidationCase(ValidationCase):
    plugin = UninstallAttributionPlugin
    test_hive_file_name = "SOFTWARE.xz"
    expected_entries = []
    expected_entries_count = 104
    custom_test = test_known_product_is_attributed_to_machine
