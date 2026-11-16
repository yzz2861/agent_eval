"""
   The MIT License (MIT)

   Copyright (C) 2020-2025 Joe Testa (jtesta@positronsecurity.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import copy
import json
import sys

from typing import Dict, List, Sequence, Tuple
from typing import Optional, Any, Union, cast
from datetime import date

from ssh_audit import exitcodes
from ssh_audit.algorithm import Algorithm
from ssh_audit.banner import Banner
from ssh_audit.builtin_policies import BUILTIN_POLICIES
from ssh_audit.globals import SNAP_PACKAGE, SNAP_PERMISSIONS_ERROR
from ssh_audit.policy_rules import PolicyRule, PolicyValidationError, compose_rule_sets, parse_algorithm_rules, validate_rules
from ssh_audit.policy_rules import TIER_BUILTIN, TIER_CLI, TIER_CUSTOM
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex


# Validates policy files and performs policy testing
class Policy:

    WARNING_DEPRECATED_DIRECTIVES = "\nWARNING: this policy is using deprecated features.  Future versions of ssh-audit may remove support for them.  Re-generating the policy file is perhaps the most straight-forward way of resolving this issue.  Manually converting the 'hostkey_size_*', 'cakey_size_*', and 'dh_modulus_size_*' directives into the new format is another option.\n"

    def __init__(self, policy_file: Optional[str] = None, policy_data: Optional[str] = None, manual_load: bool = False, json_output: bool = False) -> None:
        self._name: Optional[str] = None
        self._version: Optional[str] = None
        self._banner: Optional[str] = None
        self._compressions: Optional[List[str]] = None
        self._host_keys: Optional[List[str]] = None
        self._optional_host_keys: Optional[List[str]] = None
        self._kex: Optional[List[str]] = None
        self._ciphers: Optional[List[str]] = None
        self._macs: Optional[List[str]] = None
        self._hostkey_sizes: Optional[Dict[str, Dict[str, Union[int, str, bytes]]]] = None
        self._dh_modulus_sizes: Optional[Dict[str, int]] = None
        self._server_policy = True
        self._allow_algorithm_subset_and_reordering = False
        self._allow_hostkey_subset_and_reordering = False
        self._allow_larger_keys = False
        self._algorithm_rules: List[PolicyRule] = []  # Explicit algorithm rules (fail/warn/info) with provenance.
        self._allow_relaxation = False  # When True, this policy may weaken rules inherited from lower-precedence policies during composition.
        self._is_builtin = False  # True when loaded from BUILTIN_POLICIES.
        self._errors: List[Any] = []
        self._updated_builtin_policy_available = False  # If True, an outdated built-in policy was loaded.
        self._rule_results: List[Dict[str, Any]] = []  # Results of algorithm rule evaluation (ComposedPolicy only).

        self._name_and_version: str = ''

        # Holds raw (severity, value) pairs for the algorithm rule directives until the policy name is known.
        pending_algorithm_rules: List[Tuple[str, str]] = []

        # If invoked while JSON output is expected, send warnings to stderr instead of stdout (which would corrupt the JSON output).
        if json_output:
            self._warning_target = sys.stderr
        else:
            self._warning_target = sys.stdout

        # Ensure that only one mode was specified.
        num_modes = 0
        if policy_file is not None:
            num_modes += 1
        if policy_data is not None:
            num_modes += 1
        if manual_load is True:
            num_modes += 1

        if num_modes != 1:
            raise RuntimeError('Exactly one of the following can be specified only: policy_file, policy_data, or manual_load')

        if manual_load:
            return

        if policy_file is not None:
            try:
                with open(policy_file, "r", encoding='utf-8') as f:
                    policy_data = f.read()
            except FileNotFoundError:
                print("Error: policy file not found: %s" % policy_file)
                sys.exit(exitcodes.UNKNOWN_ERROR)
            except PermissionError as e:
                # If installed as a Snap package, print a more useful message with potential work-arounds.
                if SNAP_PACKAGE:
                    print(SNAP_PERMISSIONS_ERROR)
                else:
                    print("Error: insufficient permissions: %s" % str(e))
                sys.exit(exitcodes.UNKNOWN_ERROR)

        lines = []
        if policy_data is not None:
            lines = policy_data.split("\n")

        for line in lines:
            line = line.strip()
            if (len(line) == 0) or line.startswith('#'):
                continue

            key = None
            val = None
            try:
                key, val = line.split('=', 1)
            except ValueError as ve:
                raise ValueError("could not parse line: %s" % line) from ve

            key = key.strip()
            val = val.strip()

            if key not in ['name', 'version', 'banner', 'compressions', 'host keys', 'optional host keys', 'key exchanges', 'ciphers', 'macs', 'client policy', 'host_key_sizes', 'dh_modulus_sizes', 'allow_algorithm_subset_and_reordering', 'allow_hostkey_subset_and_reordering', 'allow_larger_keys', 'fail algorithms', 'warn algorithms', 'info algorithms', 'allow_relaxation'] and not key.startswith('hostkey_size_') and not key.startswith('cakey_size_') and not key.startswith('dh_modulus_size_'):
                raise ValueError("invalid field found in policy: %s" % line)

            if key in ['name', 'banner']:

                # If the banner value is blank, set it to "" so that the code below handles it.
                if len(val) < 2:
                    val = "\"\""

                if (val[0] != '"') or (val[-1] != '"'):
                    raise ValueError('the value for the %s field must be enclosed in quotes: %s' % (key, val))

                # Remove the surrounding quotes, and unescape quotes & newlines.
                val = val[1:-1]. replace("\\\"", "\"").replace("\\n", "\n")

                if key == 'name':
                    self._name = val
                elif key == 'banner':
                    self._banner = val

            elif key == 'version':
                self._version = val

            elif key in ['compressions', 'host keys', 'optional host keys', 'key exchanges', 'ciphers', 'macs']:
                try:
                    algs = val.split(',')
                except ValueError:
                    # If the value has no commas, then set the algorithm list to just the value.
                    algs = [val]

                # Strip whitespace in each algorithm name.
                algs = [alg.strip() for alg in algs]

                if key == 'compressions':
                    self._compressions = algs
                elif key == 'host keys':
                    self._host_keys = algs
                elif key == 'optional host keys':
                    self._optional_host_keys = algs
                elif key == 'key exchanges':
                    self._kex = algs
                elif key == 'ciphers':
                    self._ciphers = algs
                elif key == 'macs':
                    self._macs = algs

            elif key.startswith('hostkey_size_'):  # Old host key size format.
                print(Policy.WARNING_DEPRECATED_DIRECTIVES, file=self._warning_target)  # Warn the user that the policy file is using deprecated directives.

                hostkey_type = key[13:]
                hostkey_size = int(val)

                if self._hostkey_sizes is None:
                    self._hostkey_sizes = {}

                self._hostkey_sizes[hostkey_type] = {'hostkey_size': hostkey_size, 'ca_key_type': '', 'ca_key_size': 0}

            elif key.startswith('cakey_size_'):  # Old host key size format.
                print(Policy.WARNING_DEPRECATED_DIRECTIVES, file=self._warning_target)  # Warn the user that the policy file is using deprecated directives.

                hostkey_type = key[11:]
                ca_key_size = int(val)

                ca_key_type = 'ssh-ed25519'
                if hostkey_type in ['ssh-rsa-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com']:
                    ca_key_type = 'ssh-rsa'

                if self._hostkey_sizes is None:
                    self._hostkey_sizes = {}
                self._hostkey_sizes[hostkey_type] = {'hostkey_size': hostkey_size, 'ca_key_type': ca_key_type, 'ca_key_size': ca_key_size}

            elif key == 'host_key_sizes':  # New host key size format.
                self._hostkey_sizes = json.loads(val)

                # Fill in the trimmed fields that were omitted from the policy.
                self._normalize_hostkey_sizes()

            elif key.startswith('dh_modulus_size_'):  # Old DH modulus format.
                print(Policy.WARNING_DEPRECATED_DIRECTIVES, file=self._warning_target)  # Warn the user that the policy file is using deprecated directives.

                dh_type = key[16:]
                dh_size = int(val)

                if self._dh_modulus_sizes is None:
                    self._dh_modulus_sizes = {}

                self._dh_modulus_sizes[dh_type] = dh_size

            elif key == 'dh_modulus_sizes':  # New DH modulus format.
                self._dh_modulus_sizes = json.loads(val)

            elif key.startswith('client policy') and val.lower() == 'true':
                self._server_policy = False
            elif key == 'allow_algorithm_subset_and_reordering' and val.lower() == 'true':
                self._allow_algorithm_subset_and_reordering = True
                self._allow_hostkey_subset_and_reordering = True  # We force subsets/reorderings of the host keys as well in this case.
            elif key == 'allow_hostkey_subset_and_reordering' and val.lower() == 'true':
                self._allow_hostkey_subset_and_reordering = True
            elif key == 'allow_larger_keys' and val.lower() == 'true':
                self._allow_larger_keys = True
            elif key in ['fail algorithms', 'warn algorithms', 'info algorithms']:
                pending_algorithm_rules.append((key.split(' ')[0], val))
            elif key == 'allow_relaxation' and val.lower() == 'true':
                self._allow_relaxation = True

        if self._name is None:
            raise ValueError('The policy does not have a name field.')
        if self._version is None:
            raise ValueError('The policy does not have a version field.')

        self._name_and_version = "%s (version %s)" % (self._name, self._version)

        # Parse & validate the explicit algorithm rules now that the policy name is known.  Any problem (unknown algorithm, duplicate rule, contradictory fail/warn rules, illegal severity) is reported here, before any scanning occurs.
        default_scope = 'server' if self._server_policy else 'client'
        for severity, rules_value in pending_algorithm_rules:
            self._algorithm_rules.extend(parse_algorithm_rules(rules_value, severity, self._name_and_version, TIER_CUSTOM, default_scope))
        validate_rules(self._algorithm_rules, self._name_and_version)


    def _append_error(self, mismatched_field: str, expected_required: Optional[List[str]], expected_optional: Optional[List[str]], actual: List[str]) -> None:
        if expected_required is None:
            expected_required = ['']
        if expected_optional is None:
            expected_optional = ['']
        self._errors.append({'mismatched_field': mismatched_field, 'expected_required': expected_required, 'expected_optional': expected_optional, 'actual': actual})


    def _normalize_hostkey_sizes(self) -> None:
        '''Normalizes the self._hostkey_sizes structure to ensure all required fields are present.'''

        if self._hostkey_sizes is not None:
            for host_key_type in self._hostkey_sizes:
                if 'ca_key_type' not in self._hostkey_sizes[host_key_type]:
                    self._hostkey_sizes[host_key_type]['ca_key_type'] = ''
                if 'ca_key_size' not in self._hostkey_sizes[host_key_type]:
                    self._hostkey_sizes[host_key_type]['ca_key_size'] = 0
                if 'raw_hostkey_bytes' not in self._hostkey_sizes[host_key_type]:
                    self._hostkey_sizes[host_key_type]['raw_hostkey_bytes'] = b''


    @staticmethod
    def create(source: Optional[str], banner: Optional['Banner'], kex: Optional['SSH2_Kex'], client_audit: bool) -> str:
        '''Creates a policy based on a server configuration.  Returns a string.'''

        today = date.today().strftime('%Y/%m/%d')
        compressions = None
        host_keys = None
        kex_algs = None
        ciphers = None
        macs = None
        dh_modulus_sizes_str = ''
        client_policy_str = ''
        host_keys_json = ''

        if client_audit:
            client_policy_str = "\n# Set to true to signify this is a policy for clients, not servers.\nclient policy = true\n"

        if kex is not None:
            if kex.server.compression is not None:
                compressions = ', '.join(kex.server.compression)
            if kex.key_algorithms is not None:
                host_keys = ', '.join(kex.key_algorithms)
            if kex.kex_algorithms is not None:
                kex_algs = ', '.join(kex.kex_algorithms)
            if kex.server.encryption is not None:
                ciphers = ', '.join(kex.server.encryption)
            if kex.server.mac is not None:
                macs = ', '.join(kex.server.mac)

            if kex.host_keys():

                # Make a deep copy of the host keys dict, then delete all the raw hostkey bytes from the copy.
                host_keys_trimmed = copy.deepcopy(kex.host_keys())
                for hostkey_alg in host_keys_trimmed:
                    del host_keys_trimmed[hostkey_alg]['raw_hostkey_bytes']

                    # Delete the CA signature if any of its fields are empty.
                    if host_keys_trimmed[hostkey_alg]['ca_key_type'] == '' or host_keys_trimmed[hostkey_alg]['ca_key_size'] == 0:
                        del host_keys_trimmed[hostkey_alg]['ca_key_type']
                        del host_keys_trimmed[hostkey_alg]['ca_key_size']

                host_keys_json = "\n# Dictionary containing all host key and size information.  Optionally contains the certificate authority's signature algorithm ('ca_key_type') and signature length ('ca_key_size'), if any.\nhost_key_sizes = %s\n" % json.dumps(host_keys_trimmed)

            if kex.dh_modulus_sizes():
                dh_modulus_sizes_str = "\n# Group exchange DH modulus sizes.\ndh_modulus_sizes = %s\n" % json.dumps(kex.dh_modulus_sizes())


        policy_data = '''#
# Custom policy based on %s (created on %s)
#
%s
# The name of this policy (displayed in the output during scans).  Must be in quotes.
name = "Custom Policy (based on %s on %s)"

# The version of this policy (displayed in the output during scans).  Not parsed, and may be any value, including strings.
version = 1

# When false, host keys, kex, ciphers, and MAC lists must match exactly.  When true, the target host may support a subset of the specified algorithms and/or algorithms may appear in a different order; this feature is useful for specifying a baseline and allowing some hosts the option to implement stricter controls.  A value of true automatically sets "allow_hostkey_subset_and_reordering" to true as well.
allow_algorithm_subset_and_reordering = false

# When false, the host key list must match exactly.  When true, the target host may support a subset of the specified host keys and/or the keys may appear in a different order.
allow_hostkey_subset_and_reordering = true

# When false, host keys, CA keys, and Diffie-Hellman key sizes must exactly match what's specified in this policy.  When true, target systems are allowed to have larger keys; this feature is useful for specifying a baseline and allowing some hosts the option to implement stricter controls.
allow_larger_keys = false

# The banner that must match exactly.  Commented out to ignore banners, since minor variability in the banner is sometimes normal.
# banner = "%s"

# The compression options that must match exactly (order matters).  Commented out to ignore by default.
# compressions = %s
%s%s
# The host key types that must match exactly (order matters).
host keys = %s

# Host key types that may optionally appear.
#optional host keys = ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com

# The key exchange algorithms that must match exactly (order matters).
key exchanges = %s

# The ciphers that must match exactly (order matters).
ciphers = %s

# The MACs that must match exactly (order matters).
macs = %s
''' % (source, today, client_policy_str, source, today, banner, compressions, host_keys_json, dh_modulus_sizes_str, host_keys, kex_algs, ciphers, macs)

        return policy_data


    def evaluate(self, banner: Optional['Banner'], kex: Optional['SSH2_Kex']) -> Tuple[bool, List[Dict[str, str]], str]:
        '''Evaluates a server configuration against this policy.  Returns a tuple of a boolean (True if server adheres to policy) and an array of strings that holds error messages.'''

        ret = True

        banner_str = str(banner)
        if (self._banner is not None) and (banner_str != self._banner):
            ret = False
            self._append_error('Banner', [self._banner], None, [banner_str])

        # All subsequent tests require a valid kex, so end here if we don't have one.
        if kex is None:
            error_list, error_str = self._get_errors()
            return ret, error_list, error_str

        if (self._compressions is not None) and (kex.server.compression != self._compressions):
            ret = False
            self._append_error('Compression', self._compressions, None, kex.server.compression)

        # If a list of optional host keys was given in the policy, remove any of its entries from the list retrieved from the server.  This allows us to do an exact comparison with the expected list below.
        pruned_host_keys = kex.key_algorithms
        if self._optional_host_keys is not None:
            pruned_host_keys = [x for x in kex.key_algorithms if x not in self._optional_host_keys]

        # Check host keys.
        if self._host_keys is not None:
            # If the policy allows subsets and re-ordered algorithms...
            if self._allow_hostkey_subset_and_reordering:
                for hostkey_t in kex.key_algorithms:
                    if hostkey_t not in self._host_keys:
                        ret = False
                        self._append_error('Host keys', self._host_keys, self._optional_host_keys, kex.key_algorithms)
                        break
            # The policy requires exact matching of algorithms.
            elif pruned_host_keys != self._host_keys:
                ret = False
                self._append_error('Host keys', self._host_keys, self._optional_host_keys, kex.key_algorithms)

        # Check host key sizes.
        if self._hostkey_sizes is not None:
            hostkey_types = list(self._hostkey_sizes.keys())
            hostkey_types.sort()  # Sorted to make testing output repeatable.
            for hostkey_type in hostkey_types:
                expected_hostkey_size = cast(int, self._hostkey_sizes[hostkey_type]['hostkey_size'])
                server_host_keys = kex.host_keys()
                if hostkey_type in server_host_keys:
                    actual_hostkey_size = cast(int, server_host_keys[hostkey_type]['hostkey_size'])
                    if (self._allow_larger_keys and actual_hostkey_size < expected_hostkey_size) or \
                       (not self._allow_larger_keys and actual_hostkey_size != expected_hostkey_size):
                        ret = False
                        self._append_error('Host key (%s) sizes' % hostkey_type, [str(expected_hostkey_size)], None, [str(actual_hostkey_size)])

                    # If we have expected CA signatures set, check them against what the server returned.
                    if self._hostkey_sizes is not None and len(cast(str, self._hostkey_sizes[hostkey_type]['ca_key_type'])) > 0 and cast(int, self._hostkey_sizes[hostkey_type]['ca_key_size']) > 0:
                        expected_ca_key_type = cast(str, self._hostkey_sizes[hostkey_type]['ca_key_type'])
                        expected_ca_key_size = cast(int, self._hostkey_sizes[hostkey_type]['ca_key_size'])
                        actual_ca_key_type = cast(str, server_host_keys[hostkey_type]['ca_key_type'])
                        actual_ca_key_size = cast(int, server_host_keys[hostkey_type]['ca_key_size'])

                        # Ensure that the CA signature type is what's expected (i.e.: the server doesn't have an RSA sig when we're expecting an ED25519 sig).
                        if actual_ca_key_type != expected_ca_key_type:
                            ret = False
                            self._append_error('CA signature type', [expected_ca_key_type], None, [actual_ca_key_type])
                        # Ensure that the actual and expected signature sizes match.
                        elif (self._allow_larger_keys and actual_ca_key_size < expected_ca_key_size) or \
                             (not self._allow_larger_keys and actual_ca_key_size != expected_ca_key_size):
                            ret = False
                            self._append_error('CA signature size (%s)' % actual_ca_key_type, [str(expected_ca_key_size)], None, [str(actual_ca_key_size)])

        # Check key exchanges.
        if self._kex is not None:
            # If the policy allows subsets and re-ordered algorithms...
            if self._allow_algorithm_subset_and_reordering:
                for kex_t in kex.kex_algorithms:
                    if kex_t not in self._kex:
                        ret = False
                        self._append_error('Key exchanges', self._kex, None, kex.kex_algorithms)
                        break
                # If kex-strict-?-v00@openssh.com is in the policy (i.e. the Terrapin vulnerability countermeasure), then it must appear in the server's list, regardless of the "allow_algorithm_subset_and_reordering" flag.
                if ('kex-strict-s-v00@openssh.com' in self._kex and 'kex-strict-s-v00@openssh.com' not in kex.kex_algorithms) or \
                   ('kex-strict-c-v00@openssh.com' in self._kex and 'kex-strict-c-v00@openssh.com' not in kex.kex_algorithms):
                    ret = False
                    self._append_error('Key exchanges', self._kex, None, kex.kex_algorithms)

            # The policy requires exact matching of algorithms.
            elif kex.kex_algorithms != self._kex:
                ret = False
                self._append_error('Key exchanges', self._kex, None, kex.kex_algorithms)

        # Checking Ciphers
        if self._ciphers is not None:
            # If the policy allows subsets and re-ordered algorithms...
            if self._allow_algorithm_subset_and_reordering:
                for cipher_t in kex.server.encryption:
                    if cipher_t not in self._ciphers:
                        ret = False
                        self._append_error('Ciphers', self._ciphers, None, kex.server.encryption)
                        break
            # The policy requires exact matching of algorithms.
            elif kex.server.encryption != self._ciphers:
                ret = False
                self._append_error('Ciphers', self._ciphers, None, kex.server.encryption)

        # Checking MACs
        if self._macs is not None:
            # If the policy allows subsets and re-ordered algorithms...
            if self._allow_algorithm_subset_and_reordering:
                for mac_t in kex.server.mac:
                    if mac_t not in self._macs:
                        ret = False
                        self._append_error('MACs', self._macs, None, kex.server.mac)
                        break
            # The policy requires exact matching of algorithms.
            elif kex.server.mac != self._macs:
                ret = False
                self._append_error('MACs', self._macs, None, kex.server.mac)

        if self._dh_modulus_sizes is not None:
            dh_modulus_types = list(self._dh_modulus_sizes.keys())
            dh_modulus_types.sort()  # Sorted to make testing output repeatable.
            for dh_modulus_type in dh_modulus_types:
                expected_dh_modulus_size = self._dh_modulus_sizes[dh_modulus_type]
                if dh_modulus_type in kex.dh_modulus_sizes():
                    actual_dh_modulus_size = kex.dh_modulus_sizes()[dh_modulus_type]
                    if (self._allow_larger_keys and actual_dh_modulus_size < expected_dh_modulus_size) or \
                       (not self._allow_larger_keys and actual_dh_modulus_size != expected_dh_modulus_size):
                        ret = False
                        self._append_error('Group exchange (%s) modulus sizes' % dh_modulus_type, [str(expected_dh_modulus_size)], None, [str(actual_dh_modulus_size)])

        # Evaluate the explicit algorithm rules (fail/warn/info).  Fail-severity hits turn the overall result into a failure.
        rule_violation_strs = self._evaluate_algorithm_rules(banner, kex)
        if len(rule_violation_strs) > 0:
            ret = False

        error_list, error_str = self._get_errors()
        if len(rule_violation_strs) > 0:
            error_str = "\n".join([error_str] + rule_violation_strs) if len(error_str) > 0 else "\n".join(rule_violation_strs)
        return ret, error_list, error_str


    def _get_active_algorithm_rules(self) -> List['PolicyRule']:
        '''Returns the algorithm rules evaluated by this policy.  ComposedPolicy overrides this to return the merged rule set.'''
        return self._algorithm_rules


    def _evaluate_algorithm_rules(self, banner: Optional['Banner'], kex: Optional['SSH2_Kex']) -> List[str]:
        '''Evaluates the active algorithm rules against the target.  Returns a sorted list of fail-severity violation strings (with provenance); all hits are recorded in self._rule_results.'''

        self._rule_results = []
        if kex is None:
            return []

        rules = self._get_active_algorithm_rules()
        if len(rules) == 0:
            return []

        software = Software.parse(banner) if isinstance(banner, Banner) else None
        server_lists: Dict[str, List[str]] = {
            'kex': kex.kex_algorithms,
            'key': kex.key_algorithms,
            'enc': kex.server.encryption,
            'mac': kex.server.mac,
        }

        for rule in rules:
            # Rules only apply to the scope (client/server) they were written for.
            if (rule.scope == 'server') != self._server_policy:
                continue

            # Rules with a version constraint only apply when the target software matches it.
            if rule.version_constraint is not None and not rule.version_constraint.matches(software):
                continue

            for actual_alg in server_lists.get(rule.alg_type or '', []):
                if Algorithm.canonical_id(actual_alg) != rule.algorithm:
                    continue
                self._rule_results.append({
                    'algorithm': actual_alg,
                    'type': rule.alg_type,
                    'severity': rule.severity,
                    'rule': rule.spec,
                    'source': rule.source,
                    'contributors': list(rule.contributors),
                    'scope': rule.scope,
                })

        violation_strs = []
        for rule_result in self._rule_results:
            if rule_result['severity'] != 'fail':
                continue
            violation_strs.append("  * Algorithm '%s' (%s) is denied by rule '%s' (severity: fail, source: %s)." % (rule_result['algorithm'], rule_result['type'], rule_result['rule'], rule_result['source']))
        violation_strs.sort()
        return violation_strs


    def _get_errors(self) -> Tuple[List[Any], str]:
        '''Returns the list of errors, along with the string representation of those errors.'''

        all_subset_and_reordering_semicolon = "; subset and/or reordering allowed" if self._allow_algorithm_subset_and_reordering else "; exact match"
        all_subset_and_reordering_parens = " (subset and/or reordering allowed)" if self._allow_algorithm_subset_and_reordering else ""
        hostkey_subset_and_reordering_semicolon = "; subset and/or reordering allowed" if self._allow_hostkey_subset_and_reordering else "; exact match"
        hostkey_subset_and_reordering_parens = " (subset and/or reordering allowed)" if self._allow_hostkey_subset_and_reordering else ""

        error_list = []
        spacer = ''
        for e in self._errors:

            subset_and_reordering_semicolon = hostkey_subset_and_reordering_semicolon if e["mismatched_field"] == "Host keys" else all_subset_and_reordering_semicolon
            subset_and_reordering_parens = hostkey_subset_and_reordering_parens if e["mismatched_field"] == "Host keys" else all_subset_and_reordering_parens

            e_str = "  * %s did not match.\n" % e['mismatched_field']

            if ('expected_optional' in e) and (e['expected_optional'] != ['']):
                e_str += "    - Expected (required%s): %s\n    - Expected (optional): %s\n" % (subset_and_reordering_semicolon, Policy._normalize_error_field(e['expected_required']), Policy._normalize_error_field(e['expected_optional']))
                spacer = '              '
            else:
                e_str += "    - Expected%s: %s\n" % (subset_and_reordering_parens, Policy._normalize_error_field(e['expected_required']))
                spacer = '   '
            e_str += "    - Actual:%s%s\n" % (spacer, Policy._normalize_error_field(e['actual']))
            error_list.append(e_str)

        error_list.sort()  # To ensure repeatable results for testing.

        error_str = ''
        if len(error_list) > 0:
            error_str = "\n".join(error_list)

        return self._errors, error_str


    def get_name_and_version(self) -> str:
        '''Returns a string of this Policy's name and version.'''
        return self._name_and_version


    def is_outdated_builtin_policy(self) -> bool:
        '''Returns True if this is a built-in policy that has a more recent version available than currently selected.'''
        return self._updated_builtin_policy_available


    def is_server_policy(self) -> bool:
        '''Returns True if this is a server policy, or False if this is a client policy.'''
        return self._server_policy


    def is_builtin(self) -> bool:
        '''Returns True if this policy was loaded from the built-in policy database.'''
        return self._is_builtin


    def allows_relaxation(self) -> bool:
        '''Returns True if this policy explicitly declares that it may weaken inherited rules when composed with other policies.'''
        return self._allow_relaxation


    def get_algorithm_rules(self) -> List[PolicyRule]:
        '''Returns this policy's explicit algorithm rules.'''
        return self._algorithm_rules


    def get_rule_results(self) -> List[Dict[str, Any]]:
        '''Returns the results of algorithm rule evaluation (only populated for composed policies).'''
        return self._rule_results


    def get_policy_chain(self) -> List[str]:
        '''Returns the names of the policies (and command line overrides) that were composed into this policy, in precedence order.'''
        return [self._name_and_version]


    @staticmethod
    def compose(policies: Sequence['Policy'], cli_rule_specs: Optional[Sequence[str]] = None, json_output: bool = False) -> 'Policy':
        '''Composes multiple policies (and optional command line rules) into one policy with explicit, deterministic rule merging.  When a single policy is given without command line rules, it is returned unchanged.'''
        cli_rule_specs = cli_rule_specs or []
        if len(policies) == 0:
            raise PolicyValidationError('no policies were provided for composition.')
        if len(policies) == 1 and len(cli_rule_specs) == 0:
            return policies[0]
        return ComposedPolicy(policies, cli_rule_specs, json_output=json_output)


    @staticmethod
    def list_builtin_policies(verbose: bool) -> Tuple[List[str], List[str]]:
        '''Returns two lists: a list of names of built-in server policies, and a list of names of built-in client policies, respectively.'''
        server_policy_descriptions = []
        client_policy_descriptions = []

        latest_server_policies: Dict[str, Dict[str, Union[int, str]]] = {}
        latest_client_policies: Dict[str, Dict[str, Union[int, str]]] = {}
        for policy_name, policy in BUILTIN_POLICIES.items():

            # If not in verbose mode, only store the latest version of each policy.
            if not verbose:
                policy_description = "\"{:s}\"".format(policy_name)

                # Truncate the version off the policy name and obtain the version as an integer. (i.e.: "Platform X (version 3)" -> "Platform X", 3
                policy_name_no_version = ""
                version = 0
                version_pos = policy_name.find(" (version ")
                if version_pos != -1:
                    policy_name_no_version = policy_name[0:version_pos]
                    version = int(cast(str, policy['version']))  # Unit tests guarantee this to be parseable as an int.

                d = latest_server_policies if policy['server_policy'] else latest_client_policies
                if policy_name_no_version not in d:
                    d[policy_name_no_version] = {}
                    d[policy_name_no_version]['latest_version'] = version
                    d[policy_name_no_version]['description'] = policy_description
                elif version > cast(int, d[policy_name_no_version]['latest_version']):  # If an updated version of the policy was found, replace the old one.
                    d[policy_name_no_version]['latest_version'] = version
                    d[policy_name_no_version]['description'] = policy_description
            else:  # In verbose mode, return all policy versions.
                policy_description = "\"{:s}\": {:s}".format(policy_name, policy['changelog'])
                if policy['server_policy']:
                    server_policy_descriptions.append(policy_description)
                else:
                    client_policy_descriptions.append(policy_description)

        # Now that we have references to the latest policies only, add their full descriptions to the lists for returning.
        if not verbose:
            for _, dd in latest_server_policies.items():
                server_policy_descriptions.append(cast(str, dd['description']))

            for _, dd in latest_client_policies.items():
                client_policy_descriptions.append(cast(str, dd['description']))

        # Sort the lists for better readability.
        server_policy_descriptions.sort()
        client_policy_descriptions.sort()
        return server_policy_descriptions, client_policy_descriptions


    @staticmethod
    def load_builtin_policy(policy_name: str, json_output: bool = False) -> Optional['Policy']:
        '''Returns a Policy with the specified built-in policy name loaded, or None if no policy of that name exists.'''
        p = None
        if policy_name in BUILTIN_POLICIES:
            policy_struct = BUILTIN_POLICIES[policy_name]
            p = Policy(manual_load=True, json_output=json_output)
            p._is_builtin = True  # pylint: disable=protected-access
            policy_name_without_version = policy_name[0:policy_name.rfind(' (')]
            p._name = policy_name_without_version  # pylint: disable=protected-access
            p._version = cast(str, policy_struct['version'])  # pylint: disable=protected-access
            p._banner = cast(Optional[str], policy_struct['banner'])  # pylint: disable=protected-access
            p._compressions = cast(Optional[List[str]], policy_struct['compressions'])  # pylint: disable=protected-access
            p._host_keys = cast(Optional[List[str]], policy_struct['host_keys'])  # pylint: disable=protected-access
            p._optional_host_keys = cast(Optional[List[str]], policy_struct['optional_host_keys'])  # pylint: disable=protected-access
            p._kex = cast(Optional[List[str]], policy_struct['kex'])  # pylint: disable=protected-access
            p._ciphers = cast(Optional[List[str]], policy_struct['ciphers'])  # pylint: disable=protected-access
            p._macs = cast(Optional[List[str]], policy_struct['macs'])  # pylint: disable=protected-access
            p._hostkey_sizes = cast(Optional[Dict[str, Dict[str, Union[int, str, bytes]]]], policy_struct['hostkey_sizes'])  # pylint: disable=protected-access
            p._dh_modulus_sizes = cast(Optional[Dict[str, int]], policy_struct['dh_modulus_sizes'])  # pylint: disable=protected-access
            p._server_policy = cast(bool, policy_struct['server_policy'])  # pylint: disable=protected-access
            p._name_and_version = "%s (version %s)" % (p._name, p._version)  # pylint: disable=protected-access
            p._allow_hostkey_subset_and_reordering = cast(bool, policy_struct['allow_hostkey_subset_and_reordering']) if 'allow_hostkey_subset_and_reordering' in policy_struct else False  # pylint: disable=protected-access

            # Ensure this struct has all the necessary fields.
            p._normalize_hostkey_sizes()  # pylint: disable=protected-access

        # Now check if an updated version of the requested policy exists.  If so, set a warning for the user.
        if p is not None and p._version is not None:  # pylint: disable=protected-access
            next_version = str(int(p._version) + 1)  # pylint: disable=protected-access
            name_version_pos = policy_name.find("(version ")
            next_version_name = policy_name[0:name_version_pos] + "(version %s)" % next_version
            if next_version_name in BUILTIN_POLICIES:
                p._updated_builtin_policy_available = True  # pylint: disable=protected-access

        return p


    @staticmethod
    def _normalize_error_field(field: List[str]) -> Any:
        '''If field is an array with a string parsable as an integer, return that integer.  Otherwise, return the field joined with commas.'''
        if len(field) == 1:
            try:
                return int(field[0])
            except ValueError:
                return field[0]
        else:
            return ', '.join(field)


    def __str__(self) -> str:
        undefined = '{undefined}'

        name = undefined
        version = undefined
        banner = undefined
        compressions_str = undefined
        host_keys_str = undefined
        optional_host_keys_str = undefined
        kex_str = undefined
        ciphers_str = undefined
        macs_str = undefined
        hostkey_sizes_str = undefined
        dh_modulus_sizes_str = undefined


        if self._name is not None:
            name = '[%s]' % self._name
        if self._version is not None:
            version = '[%s]' % self._version
        if self._banner is not None:
            banner = '[%s]' % self._banner

        if self._compressions is not None:
            compressions_str = ', '.join(self._compressions)
        if self._host_keys is not None:
            host_keys_str = ', '.join(self._host_keys)
        if self._optional_host_keys is not None:
            optional_host_keys_str = ', '.join(self._optional_host_keys)
        if self._kex is not None:
            kex_str = ', '.join(self._kex)
        if self._ciphers is not None:
            ciphers_str = ', '.join(self._ciphers)
        if self._macs is not None:
            macs_str = ', '.join(self._macs)
        if self._hostkey_sizes is not None:
            hostkey_sizes_str = str(self._hostkey_sizes)
        if self._dh_modulus_sizes is not None:
            dh_modulus_sizes_str = str(self._dh_modulus_sizes)

        return "Name: %s\nVersion: %s\nAllow Algorithm Subset and/or Reordering: %r\nAllow Host Key Subset and/or Reordering: %r\nBanner: %s\nCompressions: %s\nHost Keys: %s\nOptional Host Keys: %s\nKey Exchanges: %s\nCiphers: %s\nMACs: %s\nHost Key Sizes: %s\nDH Modulus Sizes: %s\nServer Policy: %r" % (name, version, self._allow_algorithm_subset_and_reordering, self._allow_hostkey_subset_and_reordering, banner, compressions_str, host_keys_str, optional_host_keys_str, kex_str, ciphers_str, macs_str, hostkey_sizes_str, dh_modulus_sizes_str, self._server_policy)


    def __getstate__(self) -> Dict[str, Any]:
        '''Called when pickling this object.  The file descriptor isn't serializable, so we'll remove it from the state and include a string representation.'''

        state = self.__dict__.copy()

        if state['_warning_target'] == sys.stdout:
            state['_warning_target_type'] = 'stdout'
        else:
            state['_warning_target_type'] = 'stderr'

        del state['_warning_target']
        return state


    def __setstate__(self, state: Dict[str, Any]) -> None:
        '''Called when unpickling this object.  Based on the string representation of the file descriptor, we'll restore the right handle.'''

        if state['_warning_target_type'] == 'stdout':
            state['_warning_target'] = sys.stdout
        else:
            state['_warning_target'] = sys.stderr

        del state['_warning_target_type']
        self.__dict__.update(state)


# A policy composed of an ordered chain of policies (built-in and/or custom)
# plus optional command line rule overrides.  The first policy in the chain
# (the base policy) provides the traditional exact-match evaluation; every
# policy in the chain contributes explicit algorithm rules, which are merged
# deterministically (see policy_rules.compose_rule_sets) and evaluated with
# full provenance.
class ComposedPolicy(Policy):

    def __init__(self, policies: Sequence[Policy], cli_rule_specs: Sequence[str], json_output: bool = False) -> None:
        super().__init__(manual_load=True, json_output=json_output)

        if len(policies) == 0:
            raise PolicyValidationError('no policies were provided for composition.')

        base = policies[0]

        # All policies in the chain must share the same scope (client vs server).
        for policy in policies:
            if policy.is_server_policy() != base.is_server_policy():
                raise PolicyValidationError("cannot compose %s policy '%s' with %s policy '%s': scopes differ." % ('server' if base.is_server_policy() else 'client', base.get_name_and_version(), 'server' if policy.is_server_policy() else 'client', policy.get_name_and_version()))

        # The base policy provides the traditional exact-match evaluation fields.
        self._name = base._name  # pylint: disable=protected-access
        self._version = base._version  # pylint: disable=protected-access
        self._banner = base._banner  # pylint: disable=protected-access
        self._compressions = base._compressions  # pylint: disable=protected-access
        self._host_keys = base._host_keys  # pylint: disable=protected-access
        self._optional_host_keys = base._optional_host_keys  # pylint: disable=protected-access
        self._kex = base._kex  # pylint: disable=protected-access
        self._ciphers = base._ciphers  # pylint: disable=protected-access
        self._macs = base._macs  # pylint: disable=protected-access
        self._hostkey_sizes = base._hostkey_sizes  # pylint: disable=protected-access
        self._dh_modulus_sizes = base._dh_modulus_sizes  # pylint: disable=protected-access
        self._server_policy = base._server_policy  # pylint: disable=protected-access
        self._allow_algorithm_subset_and_reordering = base._allow_algorithm_subset_and_reordering  # pylint: disable=protected-access
        self._allow_hostkey_subset_and_reordering = base._allow_hostkey_subset_and_reordering  # pylint: disable=protected-access
        self._allow_larger_keys = base._allow_larger_keys  # pylint: disable=protected-access
        self._updated_builtin_policy_available = base._updated_builtin_policy_available  # pylint: disable=protected-access

        self._policies = list(policies)
        self._policy_chain: List[str] = [p.get_name_and_version() for p in policies]

        # Gather the rule sets from every policy in the chain, in precedence order.
        rule_sources: List[Tuple[int, str, List[PolicyRule], bool]] = []
        for policy in self._policies:
            tier = TIER_BUILTIN if policy.is_builtin() else TIER_CUSTOM
            rule_sources.append((tier, policy.get_name_and_version(), policy.get_algorithm_rules(), policy.allows_relaxation()))

        # Command line rules form the highest (and always explicit) tier.
        cli_rules: List[PolicyRule] = []
        if len(cli_rule_specs) > 0:
            default_scope = 'server' if self._server_policy else 'client'
            for spec in cli_rule_specs:
                cli_rules.extend(parse_algorithm_rules(spec, None, 'command line', TIER_CLI, default_scope))
            validate_rules(cli_rules, 'command line')
            rule_sources.append((TIER_CLI, 'command line', cli_rules, True))
            self._policy_chain.append('command line')

        self._merged_rules = compose_rule_sets(rule_sources)

        chain_str = ' + '.join(self._policy_chain)
        self._name_and_version = chain_str


    def get_policy_chain(self) -> List[str]:
        '''Returns the names of the composed policies (and command line overrides) in precedence order.'''
        return list(self._policy_chain)


    def get_merged_rules(self) -> List[PolicyRule]:
        '''Returns the final composed algorithm rules.'''
        return list(self._merged_rules.values())


    def _get_active_algorithm_rules(self) -> List[PolicyRule]:
        '''Returns the merged rule set composed from all policies and command line overrides.'''
        return list(self._merged_rules.values())
