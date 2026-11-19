## regipy Plugins

* The plugin system is a robust and extensive feature that auto-detects the hive type and execute the relevant plugins.

To see a comprehensive list, please refer to the [Validation cases report](../validation/plugin_validation.md)

## Derivation certificates

Plugin output alone cannot explain why a persistence conclusion changed after a
plugin upgrade. An opt-in derivation certificate records the evidence a plugin
actually read (key/value identities and SHA-256 digests of the original value
bytes), the plugin rule version and rule digest, and the key decision steps.
It does not embed the hive or the unrelated values that were not read.

```python
from regipy.certificate import run_plugin_with_certificate, verify_certificate
from regipy.plugins.ntuser.persistence import NTUserPersistencePlugin
from regipy.registry import RegistryHive

hive = RegistryHive("NTUSER.DAT")
plugin = NTUserPersistencePlugin(hive, as_json=True)
certificate = run_plugin_with_certificate(plugin)

result = verify_certificate(certificate, RegistryHive("NTUSER.DAT"))
assert result.status == "verified"
```

The verifier re-reads every recorded identity, compares the original-value
digests, checks the rule identity, and replays the plugin under an audit
observer. Reads that are not covered by the certificate fail verification.
Diagnostics keep the failure causes separate:

- `rule_changed` - the plugin rule version or rule digest changed.
- `input_substituted` - recorded evidence is missing, modified, or newly added.
- `unrecorded_read` - the replayed plugin needed evidence the certificate does
  not contain.
- `conclusion_mismatch` - the rule and evidence look unchanged, but the rebuilt
  conclusion or decision trace differs.

From the CLI, add `--certificate-output certificates.json` to
`regipy-plugins-run`, then verify with `regipy-verify-certificate HIVE
CERTIFICATES.json` (use a single plugin's certificate object).

## Contributing new plugins
Adding a new plugin is very straight forward:
1. Copy the `regipy/plugins/plugin_template.py` file to the relevant folder (according to hive type)
2. Update the code:
   * Update the `NAME` parameter and the Class name accordingly (NAME in snake case, Class name in camel case)
   * Feel free to use/add any utility function to `regipy/utils.py` 
   * Import your class in `regipy/plugins/__init__.py`
3. Add a [validation case](../README.md#validation-cases). This is mandatory and replaces the old regipy tests.
