import hashlib
import pytest
from datetime import date

from ssh_audit.banner import Banner
from ssh_audit.builtin_policies import BUILTIN_POLICIES
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.policy_rules import PolicyConflictError, PolicyValidationError
from ssh_audit.policy_rules import TIER_BUILTIN, TIER_CLI, TIER_CUSTOM
from ssh_audit.policy_rules import compose_rule_sets, parse_algorithm_rules
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.writebuf import WriteBuf


class TestPolicy:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = OutputBuffer
        self.Policy = Policy
        self.wbuf = WriteBuf
        self.ssh2_kex = SSH2_Kex


    def _get_kex(self):
        '''Returns an SSH2.Kex object to simulate a server connection.'''

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['kex_alg1', 'kex_alg2'])
        w.write_list(['key_alg1', 'key_alg2'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return self.ssh2_kex.parse(self.OutputBuffer, w.write_flush())


    def test_builtin_policy_consistency(self):
        '''Ensure that the BUILTIN_POLICIES struct is consistent.'''

        for policy_name in BUILTIN_POLICIES:

            # Ensure that all required fields are present.
            required_fields = ['version', 'changelog', 'banner', 'compressions', 'host_keys', 'optional_host_keys', 'kex', 'ciphers', 'macs', 'hostkey_sizes', 'dh_modulus_sizes', 'server_policy']
            for field in required_fields:
                assert field in BUILTIN_POLICIES[policy_name]

            # Ensure that the policy name ends with " (version X)", where X is the 'version' field.
            version_str = " (version %s)" % BUILTIN_POLICIES[policy_name]['version']
            assert policy_name.endswith(version_str)

            # Ensure version field is a string, but can be parsed as an integer.
            version_field = BUILTIN_POLICIES[policy_name]['version']
            assert type(version_field) is str
            try:
                int(version_field)
            except ValueError:
                assert False, "version field of %s policy is not parseable as an integer." % policy_name

            # Ensure that the changelog field is a string and non-empty.
            assert type(BUILTIN_POLICIES[policy_name]['changelog']) is str
            assert len(BUILTIN_POLICIES[policy_name]['changelog']) > 0

            # Ensure that at least one host key is defined.
            assert type(BUILTIN_POLICIES[policy_name]['host_keys']) is list
            assert len(BUILTIN_POLICIES[policy_name]['host_keys']) > 0

            # Ensure that at least one key exchange is defined.
            assert type(BUILTIN_POLICIES[policy_name]['kex']) is list
            assert len(BUILTIN_POLICIES[policy_name]['kex']) > 0

            # Ensure that at least one cipher is defined.
            assert type(BUILTIN_POLICIES[policy_name]['ciphers']) is list
            assert len(BUILTIN_POLICIES[policy_name]['ciphers']) > 0

            # Ensure that at least one MAC is defined
            assert type(BUILTIN_POLICIES[policy_name]['macs']) is list
            assert len(BUILTIN_POLICIES[policy_name]['macs']) > 0

            # These tests apply to server policies only.
            if BUILTIN_POLICIES[policy_name]['server_policy']:
                assert type(BUILTIN_POLICIES[policy_name]['hostkey_sizes']) is dict
                assert len(BUILTIN_POLICIES[policy_name]['hostkey_sizes']) > 0

                # Examine all the hostkey_sizes entries...
                for hostkey_type in BUILTIN_POLICIES[policy_name]['hostkey_sizes']:
                    hostkey_data = BUILTIN_POLICIES[policy_name]['hostkey_sizes'][hostkey_type]

                    # Ensure that 'hostkey_size' is always included and that it is an integer.
                    assert 'hostkey_size' in hostkey_data
                    assert type(hostkey_data['hostkey_size']) is int

                    # If this is an ed25519 host key, ensure its size is fixed at 256.  If its an RSA host key, ensure the size is 4096.
                    if hostkey_type.find('ed25519') != -1:
                        assert int(hostkey_data['hostkey_size']) == 256
                    elif hostkey_type.startswith('rsa-'):
                        assert int(hostkey_data['hostkey_size']) == 4096
                    else:  # Catch unexpected host key types.
                        assert False

                    # Ensure either that 'ca_key_type' and 'ca_key_size' are both present, or neither are.  Fail cases when only one of the fields are present.
                    assert (('ca_key_type' in hostkey_data) and ('ca_key_size' in hostkey_data)) or (('ca_key_type' not in hostkey_data) and ('ca_key_size' not in hostkey_data))

                    # Ensure that the ca_key_type is either ssh-rsa or ssh-ed25519.
                    if 'ca_key_type' in hostkey_data:
                        assert hostkey_data['ca_key_type'] in ['ssh-rsa', 'ssh-ed25519']

                    # Ensure RSA CA key sizes are fixed at 4096.  Ensure ED25519 CA keys are 256.
                    if 'ca_key_size' in hostkey_data:
                        if 'ca_key_type' == 'ssh-rsa':
                            assert hostkey_data['ca_key_size'] == 4096
                        elif 'ca_key_type' == 'ssh-ed25519':
                            assert hostkey_data['ca_key_size'] == 256

                # Ensure that the 'dh_modulus_size' field is a dict.
                assert type(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']) is dict

                # The 'dh_modulus_size' field should have either one entry, or be empty.
                assert len(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']) in range(0, 2)  # The endpoint in range() is not inclusive

                # If 'diffie-hellman-group-exchange-sha256' is in the kex list, ensure that it exists in the 'dh_modulus_sizes' entry.  That entry must be defined for 2048 bits or larger.
                if 'diffie-hellman-group-exchange-sha256' in BUILTIN_POLICIES[policy_name]['kex']:
                    assert 'diffie-hellman-group-exchange-sha256' in BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']
                    assert int(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']['diffie-hellman-group-exchange-sha256']) >= 2048

            else:  # Client-specific tests.

                # These must be set to None for client policies, since they have no meaning otherwise.
                assert BUILTIN_POLICIES[policy_name]['hostkey_sizes'] is None
                assert BUILTIN_POLICIES[policy_name]['dh_modulus_sizes'] is None

            # Ensure that each built-in policy can be loaded with Policy.load_builtin_policy().
            assert Policy.load_builtin_policy(policy_name) is not None

        # Ensure that both server and client policy names are returned.
        server_policy_names, client_policy_names = Policy.list_builtin_policies(False)
        assert len(server_policy_names) > 0
        assert len(client_policy_names) > 0


    def test_policy_basic(self):
        '''Ensure that a basic policy can be parsed correctly.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        assert str(policy) == "Name: [Test Policy]\nVersion: [1]\nAllow Algorithm Subset and/or Reordering: False\nAllow Host Key Subset and/or Reordering: False\nBanner: {undefined}\nCompressions: comp_alg1\nHost Keys: key_alg1\nOptional Host Keys: {undefined}\nKey Exchanges: kex_alg1, kex_alg2\nCiphers: cipher_alg1, cipher_alg2, cipher_alg3\nMACs: mac_alg1, mac_alg2, mac_alg3\nHost Key Sizes: {undefined}\nDH Modulus Sizes: {undefined}\nServer Policy: True"


    def test_policy_invalid_1(self):
        '''Basic policy, but with 'ciphersx' instead of 'ciphers'.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphersx = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_2(self):
        '''Basic policy, but is missing the required name field.'''

        policy_data = '''# This is a comment
#name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_3(self):
        '''Basic policy, but is missing the required version field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
#version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_4(self):
        '''Basic policy, but is missing quotes in the name field.'''

        policy_data = '''# This is a comment
name = Test Policy
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_5(self):
        '''Basic policy, but is missing quotes in the banner field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

banner = 0mg
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_6(self):
        '''Basic policy, but is missing quotes in the header field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

header = 0mg
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_create_1(self):
        '''Creates a policy from a kex and ensures it is generated exactly as expected.'''

        kex = self._get_kex()
        pol_data = self.Policy.create('www.l0l.com', 'bannerX', kex, False)

        # Today's date is embedded in the policy, so filter it out to get repeatable results.
        pol_data = pol_data.replace(date.today().strftime('%Y/%m/%d'), '[todays date]')

        # Instead of writing out the entire expected policy--line by line--just check that it has the expected hash.
        assert hashlib.sha256(pol_data.encode('ascii')).hexdigest() == '3862e56ea60c1ecba6dffbf724216c4391b6fe00a790b0075617477d4addf761'


    def test_policy_evaluate_passing_1(self):
        '''Creates a policy and evaluates it against the same server'''

        kex = self._get_kex()
        policy_data = self.Policy.create('www.l0l.com', None, kex, False)
        policy = self.Policy(policy_data=policy_data)

        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0
        print(error_str)
        assert len(error_str) == 0


    def test_policy_evaluate_failing_1(self):
        '''Ensure that a policy with a specified banner fails against a server with a different banner'''

        policy_data = '''name = "Test Policy"
version = 1
banner = "XXX mismatched banner XXX"
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Banner did not match.') != -1


    def test_policy_evaluate_failing_2(self):
        '''Ensure that a mismatched compressions list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = XXXmismatchedXXX, comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Compression did not match.') != -1


    def test_policy_evaluate_failing_3(self):
        '''Ensure that a mismatched host keys results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = XXXmismatchedXXX, key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Host keys did not match.') != -1


    def test_policy_evaluate_failing_4(self):
        '''Ensure that a mismatched key exchange list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = XXXmismatchedXXX, kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Key exchanges did not match.') != -1


    def test_policy_evaluate_failing_5(self):
        '''Ensure that a mismatched cipher list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, XXXmismatched, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Ciphers did not match.') != -1


    def test_policy_evaluate_failing_6(self):
        '''Ensure that a mismatched MAC list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, XXXmismatched, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('MACs did not match.') != -1


    def test_policy_evaluate_failing_7(self):
        '''Ensure that a mismatched host keys and MACs results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2, XXXmismatchedXXX
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, XXXmismatchedXXX, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 2
        assert error_str.find('Host keys did not match.') != -1
        assert error_str.find('MACs did not match.') != -1


    def test_policy_evaluate_subset_passing_1(self):
        '''Ensure that exact algorithm matches work even when subset parsing is enabled.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""


    def test_policy_evaluate_subset_passing_2(self):
        '''Ensure that subset parsing works.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""


    def test_policy_evaluate_subset_failing_1(self):
        '''Ensure that subset parsing returns a failure.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg7, key_alg8, key_alg9
key exchanges = kex_alg7, kex_alg8, kex_alg9
ciphers = cipher_alg7, cipher_alg8, cipher_alg9, cipher_alg10
macs = mac_alg7, mac_alg8, mac_alg9, mac_alg10'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 4
        assert error_str.find("Ciphers did not match.") != -1
        assert error_str.find("Host keys did not match.") != -1
        assert error_str.find("MACs did not match") != -1
        assert error_str.find("Key exchanges did not match.") != -1


    def test_policy_evaluate_subset_failing_2(self):
        '''Ensure that subset parsing returns a failure when policy includes kex-strict-s-v00@openssh.com, but target does not.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2, kex-strict-s-v00@openssh.com
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find("Key exchanges did not match.") != -1


    def _get_kex_with_real_algs(self, kex_algs=None, key_algs=None, enc_algs=None, mac_algs=None):
        '''Returns an SSH2.Kex object with real algorithm names, for testing algorithm rules.'''

        kex_algs = kex_algs if kex_algs is not None else ['curve25519-sha256']
        key_algs = key_algs if key_algs is not None else ['ssh-ed25519']
        enc_algs = enc_algs if enc_algs is not None else ['aes128-ctr']
        mac_algs = mac_algs if mac_algs is not None else ['hmac-sha2-256']

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(kex_algs)
        w.write_list(key_algs)
        w.write_list(enc_algs)
        w.write_list(enc_algs)
        w.write_list(mac_algs)
        w.write_list(mac_algs)
        w.write_list(['none'])
        w.write_list(['none'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return self.ssh2_kex.parse(self.OutputBuffer, w.write_flush())


    def test_policy_algorithm_rules_parsing(self):
        '''Ensure that fail/warn algorithm rule directives are parsed with scope, type resolution, and canonicalization.'''

        policy_data = '''name = "Rule Policy"
version = 1
fail algorithms = kex:diffie-hellman-group1-sha1, ssh-rsa
warn algorithms = client:enc:aes128-cbc
'''
        policy = self.Policy(policy_data=policy_data)
        rules = policy.get_algorithm_rules()
        assert len(rules) == 3

        by_alg = {r.algorithm: r for r in rules}
        assert by_alg['diffie-hellman-group1-sha1'].severity == 'fail'
        assert by_alg['diffie-hellman-group1-sha1'].alg_type == 'kex'
        assert by_alg['diffie-hellman-group1-sha1'].scope == 'server'  # Default scope follows the policy type.
        assert by_alg['ssh-rsa'].alg_type == 'key'  # Type resolved from the database.
        assert by_alg['aes128-cbc'].severity == 'warn'
        assert by_alg['aes128-cbc'].scope == 'client'

        # Every rule carries its source policy for provenance.
        for rule in rules:
            assert rule.source == 'Rule Policy (version 1)'


    def test_policy_rules_unknown_algorithm(self):
        '''Unknown algorithms in rules must be rejected before scanning.'''

        policy_data = '''name = "Bad Policy"
version = 1
fail algorithms = kex:no-such-algorithm
'''
        with pytest.raises(PolicyValidationError):
            self.Policy(policy_data=policy_data)


    def test_policy_rules_duplicate_via_alias(self):
        '''Aliases normalize to the same canonical id, so two spellings of one algorithm are a duplicate rule.'''

        policy_data = '''name = "Bad Policy"
version = 1
fail algorithms = kex:sntrup761x25519-sha512@openssh.com, kex:sntrup761x25519-sha512
'''
        with pytest.raises(PolicyValidationError):
            self.Policy(policy_data=policy_data)


    def test_policy_rules_contradictory_fail_warn(self):
        '''A policy that both fails and warns on the same canonical algorithm is contradictory.'''

        policy_data = '''name = "Bad Policy"
version = 1
fail algorithms = ssh-rsa
warn algorithms = key:ssh-rsa
'''
        with pytest.raises(PolicyValidationError):
            self.Policy(policy_data=policy_data)


    def test_policy_rules_invalid_severity(self):
        '''Illegal severities are rejected.'''

        with pytest.raises(PolicyValidationError):
            parse_algorithm_rules('critical:kex:diffie-hellman-group1-sha1', None, 'test', TIER_CLI, 'server')


    def test_policy_compose_single_policy_unchanged(self):
        '''A single policy without command line rules is returned as-is (legacy behavior).'''

        policy = self.Policy.load_builtin_policy('Hardened Debian 12 (version 3)')
        assert self.Policy.compose([policy]) is policy


    def test_policy_compose_scope_mismatch(self):
        '''Server and client policies cannot be composed together.'''

        server_policy = self.Policy(policy_data='name = "Server"\nversion = 1\n')
        client_policy = self.Policy(policy_data='name = "Client"\nversion = 1\nclient policy = true\n')
        with pytest.raises(PolicyValidationError):
            self.Policy.compose([server_policy, client_policy])


    def test_rule_merge_strictest_wins(self):
        '''Rules from different precedence tiers resolve to the strictest severity, with provenance.'''

        builtin_rules = parse_algorithm_rules('kex:diffie-hellman-group1-sha1', 'fail', 'Builtin (version 1)', TIER_BUILTIN, 'server')
        custom_rules = parse_algorithm_rules('kex:diffie-hellman-group1-sha1', 'warn', 'Custom (version 1)', TIER_CUSTOM, 'server')
        merged = compose_rule_sets([(TIER_BUILTIN, 'Builtin (version 1)', builtin_rules, False), (TIER_CUSTOM, 'Custom (version 1)', custom_rules, False)])

        assert len(merged) == 1
        rule = list(merged.values())[0]
        assert rule.severity == 'fail'  # The custom policy may not weaken the built-in fail rule.
        assert rule.source == 'Builtin (version 1)'
        assert 'Custom (version 1)' in rule.contributors


    def test_rule_merge_custom_tightens(self):
        '''A custom policy may tighten a rule inherited from a built-in policy.'''

        builtin_rules = parse_algorithm_rules('kex:diffie-hellman-group1-sha1', 'warn', 'Builtin (version 1)', TIER_BUILTIN, 'server')
        custom_rules = parse_algorithm_rules('kex:diffie-hellman-group1-sha1', 'fail', 'Custom (version 1)', TIER_CUSTOM, 'server')
        merged = compose_rule_sets([(TIER_BUILTIN, 'Builtin (version 1)', builtin_rules, False), (TIER_CUSTOM, 'Custom (version 1)', custom_rules, False)])

        rule = list(merged.values())[0]
        assert rule.severity == 'fail'
        assert rule.source == 'Custom (version 1)'


    def test_rule_merge_relaxation_requires_declaration(self):
        '''A custom policy may only weaken an inherited rule when it declares allow_relaxation.'''

        # With allow_relaxation declared, the custom policy's weaker severity wins.
        builtin_rules = parse_algorithm_rules('kex:diffie-hellman-group1-sha1', 'fail', 'Builtin (version 1)', TIER_BUILTIN, 'server')
        custom_rules = parse_algorithm_rules('kex:diffie-hellman-group1-sha1', 'warn', 'Custom (version 1)', TIER_CUSTOM, 'server')
        merged = compose_rule_sets([(TIER_BUILTIN, 'Builtin (version 1)', builtin_rules, False), (TIER_CUSTOM, 'Custom (version 1)', custom_rules, True)])

        rule = list(merged.values())[0]
        assert rule.severity == 'warn'
        assert rule.source == 'Custom (version 1)'


    def test_rule_merge_same_tier_conflict(self):
        '''Two rules at the same precedence tier with different severities are a hard conflict.'''

        rules_a = parse_algorithm_rules('ssh-rsa', 'fail', 'Policy A (version 1)', TIER_CUSTOM, 'server')
        rules_b = parse_algorithm_rules('key:ssh-rsa', 'warn', 'Policy B (version 1)', TIER_CUSTOM, 'server')
        with pytest.raises(PolicyConflictError):
            compose_rule_sets([(TIER_CUSTOM, 'Policy A (version 1)', rules_a, False), (TIER_CUSTOM, 'Policy B (version 1)', rules_b, False)])


    def test_rule_merge_cli_override(self):
        '''Command line rules take final precedence, even when weakening.'''

        policy_data = '''name = "Custom"
version = 1
fail algorithms = key:ssh-rsa
'''
        policy = self.Policy(policy_data=policy_data)
        composed = self.Policy.compose([policy], ['info:key:ssh-rsa'])

        merged = composed.get_merged_rules()
        assert len(merged) == 1
        assert merged[0].severity == 'info'
        assert merged[0].source == 'command line'
        assert composed.get_policy_chain() == ['Custom (version 1)', 'command line']


    def test_policy_evaluate_fail_rule(self):
        '''A fail-severity rule hit fails the evaluation and reports the source policy and rule.'''

        policy_data = '''name = "Custom"
version = 1
fail algorithms = kex:diffie-hellman-group1-sha1
'''
        policy = self.Policy(policy_data=policy_data)
        kex = self._get_kex_with_real_algs(kex_algs=['diffie-hellman-group1-sha1', 'curve25519-sha256'])

        ret, errors, error_str = policy.evaluate(None, kex)
        assert ret is False
        assert error_str.find("Algorithm 'diffie-hellman-group1-sha1' (kex) is denied by rule 'kex:diffie-hellman-group1-sha1'") != -1
        assert error_str.find("source: Custom (version 1)") != -1

        results = policy.get_rule_results()
        assert len(results) == 1
        assert results[0]['algorithm'] == 'diffie-hellman-group1-sha1'
        assert results[0]['severity'] == 'fail'
        assert results[0]['source'] == 'Custom (version 1)'


    def test_policy_evaluate_warn_rule_passes(self):
        '''A warn-severity rule hit does not fail the evaluation, but is reported with provenance.'''

        policy_data = '''name = "Custom"
version = 1
warn algorithms = enc:aes128-cbc
'''
        policy = self.Policy(policy_data=policy_data)
        kex = self._get_kex_with_real_algs(enc_algs=['aes128-cbc'])

        ret, errors, error_str = policy.evaluate(None, kex)
        assert ret is True
        assert len(error_str) == 0

        results = policy.get_rule_results()
        assert len(results) == 1
        assert results[0]['algorithm'] == 'aes128-cbc'
        assert results[0]['severity'] == 'warn'
        assert results[0]['source'] == 'Custom (version 1)'


    def test_policy_evaluate_rule_alias_hit(self):
        '''A rule written with one spelling hits a server advertising an alias spelling.'''

        policy_data = '''name = "Custom"
version = 1
fail algorithms = kex:sntrup761x25519-sha512@openssh.com
'''
        policy = self.Policy(policy_data=policy_data)
        kex = self._get_kex_with_real_algs(kex_algs=['sntrup761x25519-sha512'])

        ret, errors, error_str = policy.evaluate(None, kex)
        assert ret is False
        assert error_str.find("Algorithm 'sntrup761x25519-sha512' (kex) is denied") != -1


    def test_policy_evaluate_version_constraint(self):
        '''Rules with version constraints only apply when the target software matches the range.'''

        policy_data = '''name = "Custom"
version = 1
fail algorithms = kex:curve25519-sha256@openssh>=9.0
'''
        policy = self.Policy(policy_data=policy_data)
        kex = self._get_kex_with_real_algs(kex_algs=['curve25519-sha256'])

        # OpenSSH 8.5 does not match the constraint, so the rule does not apply.
        ret, _, _ = policy.evaluate(Banner.parse('SSH-2.0-OpenSSH_8.5'), kex)
        assert ret is True
        assert len(policy.get_rule_results()) == 0

        # OpenSSH 9.6 matches, so the rule fires.
        ret, _, error_str = policy.evaluate(Banner.parse('SSH-2.0-OpenSSH_9.6'), kex)
        assert ret is False
        assert error_str.find("curve25519-sha256") != -1


    def test_policy_compose_stacked_evaluation(self):
        '''Stacking a built-in policy, a custom policy, and a CLI override yields a composed policy whose results carry provenance.'''

        builtin = self.Policy.load_builtin_policy('Hardened Debian 12 (version 3)')
        assert builtin is not None

        custom = self.Policy(policy_data='''name = "Customer Baseline"
version = 1
warn algorithms = enc:aes128-cbc
''')
        composed = self.Policy.compose([builtin, custom], ['fail:mac:hmac-md5'])

        assert composed.get_policy_chain() == ['Hardened Debian 12 (version 3)', 'Customer Baseline (version 1)', 'command line']
        assert composed.get_name_and_version().find('Customer Baseline') != -1

        kex = self._get_kex_with_real_algs(enc_algs=['aes128-cbc'], mac_algs=['hmac-md5'])
        ret, _, error_str = composed.evaluate(None, kex)
        assert ret is False  # The CLI fail rule on hmac-md5 fires.
        assert error_str.find("source: command line") != -1

        results = composed.get_rule_results()
        by_sev = {r['severity']: r for r in results}
        assert by_sev['fail']['source'] == 'command line'
        assert by_sev['fail']['algorithm'] == 'hmac-md5'
        assert by_sev['warn']['source'] == 'Customer Baseline (version 1)'
        assert by_sev['warn']['algorithm'] == 'aes128-cbc'


    def test_policy_evaluate_subset_failing_3(self):
        '''Ensure that subset parsing returns a failure when policy includes kex-strict-c-v00@openssh.com, but target does not.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2, kex-strict-c-v00@openssh.com
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find("Key exchanges did not match.") != -1
