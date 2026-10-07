# encoding: ASCII-8BIT
# frozen_string_literal: false

require_relative '../common'
require 'base64'
require 'net/ssh/authentication/security_key'
require 'net/ssh/key_factory'
require 'tempfile'

class TestSecurityKey < NetSSHTest
  SK = Net::SSH::Authentication::SecurityKey

  # Fixed local samples. The Ed25519 signatures are deterministic. The
  # ECDSA key and signatures were generated once against these exact
  # inputs and frozen as base64; no hardware device is involved.
  ED_SEED = Base64.decode64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=')
  ED_PUB = Base64.decode64('A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=')
  EC_POINT = Base64.decode64(
    'BCYM1zC18XUzefWjod1CJQlrexvRzMeIrdLIv4+Y2Q/eFq3eOgvcILtu4xyvprihA4VF0NG5Da0Wpc4oXSO+7cw='
  )
  DATA = Base64.decode64('c2Vzc2lvbi1zaWduYXR1cmUtcGF5bG9hZA==')

  ED_PUBKEY_BLOB = Base64.decode64(
    'AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4AAAABHNzaDo='
  )
  EC_PUBKEY_BLOB = Base64.decode64(
    'AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBCYM1zC18XUzefWjod1CJQlrexvRzMeIrdLIv4+Y2Q/eFq3eOgvcILtu4xyvprihA4VF0NG5Da0Wpc4oXSO+7cwAAAAEc3NoOg=='
  )

  ED_UP = Base64.decode64('AAAABHNzaDoBAAAAKgAAAEC++fyEayLLOC3YQW9qoCziZu4VIuCQJn3YwYXDYspUx8z7FCKrGOLkIboYI/KsHklAHsOKkkMYc1vfBOdVF1gK')
  ED_UV = Base64.decode64('AAAABHNzaDoFAAAAKwAAAEBJA+zm2MBhRZ4M2SAuO6Vbw7gXWzW/5vqsXpJ8YK1UZMWOUxnyAX4jsDqRpXgTP1Xpv+QxbjIMKxJ3sA37mvkC')
  ED_NO_UP = Base64.decode64('AAAABHNzaDoAAAAALAAAAECdmKa2ADBeJFBMVREFtSNTKhzbv6BBV0fllN1UaRUOePzdNlszg/QbwmUf/8V4SyIb4pddRFViF17N361kzYkB')
  ED_WRONG_APP = Base64.decode64('AAAACXNzaDpvdGhlcgEAAAAqAAAAQMAAvxdNQCPrEnfnGN4pHj05+Ev5TGAi5NpBT2VqhkzA9+s5vdEScwnnPNNkpyIFN3apipt3r80Nw9Ya0nyPzQc=')

  EC_UP = Base64.decode64('AAAABHNzaDoBAAAABwAAAEkAAAAgZUTgWzClpzfs9P7WtmDof3sybX+iTAJVaeUan0UkM9MAAAAhAMxTLL+DKtL348hYZ3kow48ZecV0LLtYZjrYTXcVZKcb')
  EC_UV = Base64.decode64('AAAABHNzaDoFAAAACAAAAEoAAAAhANk0IxMpA8prGtpKLQHLeSGsP9Nb3LC+4KZIbgPFRWjFAAAAIQDic1Zi03OZ494/Z04zIEZf281jrP3VoFaEtnia9/YBsw==')
  EC_NO_UP = Base64.decode64('AAAABHNzaDoAAAAACQAAAEoAAAAhAIBlq9CaqQhnHSjsNY9pkA+/bs2nt/FOgB4A8bMtNKeZAAAAIQD9wbcFdb4Dyypobkvt0gmKcVlUN8vCkWmaWxqJjDBMyw==')
  EC_WRONG_APP = Base64.decode64('AAAACXNzaDpvdGhlcgEAAAAHAAAASAAAACAbZkMmkM2uLUd0hvA3UH4xOa+0rIXzKy01QJopmx7tXgAAACA6Mm5hkY9UASxBj3JEelZ5BgKHrua0QMjOjkE+CNCQew==')

  UP = SK::FLAG_USER_PRESENT
  UP_AND_UV = SK::FLAG_USER_PRESENT | SK::FLAG_USER_VERIFIED

  def setup
    @ed_key = SK::Ed25519PubKey.new(ED_PUB, 'ssh:')
    @ec_key = SK::ECDSAPubKey.new('nistp256', EC_POINT, 'ssh:')
  end

  def test_wire_types
    assert_equal 'sk-ssh-ed25519@openssh.com', @ed_key.ssh_type
    assert_equal @ed_key.ssh_type, @ed_key.ssh_signature_type
    assert_equal 'sk-ecdsa-sha2-nistp256@openssh.com', @ec_key.ssh_type
    assert_equal @ec_key.ssh_type, @ec_key.ssh_signature_type
  end

  def test_public_key_blob_roundtrip
    [ED_PUBKEY_BLOB, EC_PUBKEY_BLOB].each do |blob|
      parsed = Net::SSH::Buffer.new(blob).read_key
      assert_equal blob, parsed.to_blob
    end
  end

  def test_ed25519_public_key_blob_fields
    key = Net::SSH::Buffer.new(ED_PUBKEY_BLOB).read_key
    assert_instance_of SK::Ed25519PubKey, key
    assert_equal ED_PUB, key.public_key_bytes
    assert_equal 'ssh:', key.application
  end

  def test_ecdsa_public_key_blob_fields
    key = Net::SSH::Buffer.new(EC_PUBKEY_BLOB).read_key
    assert_instance_of SK::ECDSAPubKey, key
    assert_equal 'nistp256', key.curve_name
    assert_equal 'ssh:', key.application
  end

  def test_ed25519_public_key_defaults_application
    assert_equal 'ssh:', SK::Ed25519PubKey.new(ED_PUB).application
  end

  def test_read_public_key_line
    line = "#{@ed_key.ssh_type} #{[ED_PUBKEY_BLOB].pack('m0').gsub(/\s/, '')} comment\n"
    loaded = Net::SSH::KeyFactory.load_data_public_key(line)
    assert_equal ED_PUBKEY_BLOB, loaded.to_blob
  end

  def test_known_hosts_roundtrip
    Tempfile.open('sk_known_hosts') do |file|
      encoded = [ED_PUBKEY_BLOB].pack('m0').gsub(/\s/, '')
      file.write("# sk comment\nexample.test #{@ed_key.ssh_type} #{encoded}\n")
      file.flush
      keys = Net::SSH::KnownHosts.new(file.path).keys_for('example.test')
      assert_equal 1, keys.count
      assert_equal @ed_key.ssh_type, keys.first.ssh_type
      assert_equal ED_PUBKEY_BLOB, keys.first.to_blob
    end
  end

  def test_signature_blob_roundtrip
    inner = 'inner-signature'
    blob = SK.encode_signature_blob('ssh:', UP, 42, inner)
    application, flags, counter, signature = SK.read_signature_blob(blob)
    assert_equal ['ssh:', UP, 42, inner], [application, flags, counter, signature]
  end

  def test_ed25519_verify_success
    assert @ed_key.ssh_do_verify(ED_UP, DATA, {})
  end

  def test_ecdsa_verify_success
    assert @ec_key.ssh_do_verify(EC_UP, DATA, {})
  end

  def test_verify_rejects_modified_data
    refute @ed_key.ssh_do_verify(ED_UP, DATA + 'tampered', {})
    refute @ec_key.ssh_do_verify(EC_UP, DATA + 'tampered', {})
  end

  def test_verify_rejects_modified_application
    assert_raises(SK::SecurityKeyError) { SK.verify(@ed_key, ED_WRONG_APP, DATA) }
    assert_raises(SK::SecurityKeyError) { SK.verify(@ec_key, EC_WRONG_APP, DATA) }
    refute @ed_key.ssh_do_verify(ED_WRONG_APP, DATA, {})
    refute @ec_key.ssh_do_verify(EC_WRONG_APP, DATA, {})
  end

  def test_application_in_key_is_used_for_verification
    app = 'https://example.test'
    key = SK::Ed25519PubKey.new(ED_PUB, app)
    sign_key = OpenSSL::PKey.new_raw_private_key('ED25519', ED_SEED)
    message = SK.authenticator_message(app, UP, 1, DATA)
    blob = SK.encode_signature_blob(app, UP, 1, sign_key.sign(nil, message))
    assert key.ssh_do_verify(blob, DATA, {})
  end

  def test_user_presence_is_required_by_default
    assert_raises(SK::SecurityKeyError) { SK.verify(@ed_key, ED_NO_UP, DATA) }
    assert_raises(SK::SecurityKeyError) { SK.verify(@ec_key, EC_NO_UP, DATA) }
  end

  def test_user_presence_policy_can_be_relaxed
    result = SK.verify(@ed_key, ED_NO_UP, DATA, user_presence_required: false)
    refute result.user_present?
  end

  def test_user_verification_required_by_caller_policy
    result = SK.verify(@ed_key, ED_UV, DATA, user_verification_required: true)
    assert result.user_verified?
    assert result.user_present?

    error = assert_raises(SK::SecurityKeyError) do
      SK.verify(@ed_key, ED_UP, DATA, user_verification_required: true)
    end
    assert_match(/user verification/, error.message)

    assert @ec_key.ssh_do_verify(EC_UV, DATA, user_verification_required: true)
    refute @ec_key.ssh_do_verify(EC_UP, DATA, user_verification_required: true)
  end

  def test_uv_not_required_accepts_uv_signature
    assert @ed_key.ssh_do_verify(ED_UV, DATA, {})
    assert @ec_key.ssh_do_verify(EC_UV, DATA, {})
  end

  def test_counter_is_exposed_without_global_state
    options = {}
    @ed_key.ssh_do_verify(ED_UP, DATA, options)
    result = options[:security_key_result]
    assert_instance_of SK::Result, result
    assert_equal 42, result.counter
    assert_equal UP, result.flags
    assert_equal 'ssh:', result.application
    assert result.user_present?
    refute result.user_verified?

    direct = SK.verify(@ec_key, EC_UP, DATA)
    assert_equal 7, direct.counter

    # A second verification returns a fresh result; nothing is remembered.
    other = SK.verify(@ec_key, EC_UP, DATA)
    refute_same result, direct
    refute_same direct, other
  end

  def test_truncated_signature_is_rejected
    [[@ed_key, ED_UP], [@ec_key, EC_UP]].each do |key, blob|
      [0, 1, 4, 10, blob.bytesize - 1].each do |length|
        refute key.ssh_do_verify(blob[0, length], DATA, {})
        assert_raises(SK::SecurityKeyError) { SK.verify(key, blob[0, length], DATA) }
      end
    end
  end

  def test_trailing_bytes_are_rejected
    [ED_UP, EC_UP].each do |blob|
      assert_raises(SK::SecurityKeyError) { SK.read_signature_blob(blob + 'X') }
    end
  end

  def test_inner_signature_is_never_verified_as_plain_key
    # Pull the inner signature out and confirm it is not accepted as a raw
    # Ed25519/ECDSA signature over DATA.
    _app, _flags, _counter, inner = SK.read_signature_blob(ED_UP)
    raw_ed = Net::SSH::Authentication::ED25519.new_public_key(ED_PUB)
    refute Net::SSH::Authentication::ED25519.verify(raw_ed, inner, DATA)

    _app, _flags, _counter, ec_inner = SK.read_signature_blob(EC_UP)
    refute @ec_key.openssl_key.ssh_do_verify(ec_inner, DATA)
  end

  def test_flags_are_exposed
    result = SK.verify(@ed_key, ED_UV, DATA)
    assert_equal UP_AND_UV, result.flags
    assert result.user_present?
    assert result.user_verified?
  end

  def test_unsupported_ecdsa_curve_is_rejected
    error = assert_raises(SK::SecurityKeyError) do
      SK::ECDSAPubKey.new('nistp384', '\x04' + '\x00' * 96, 'ssh:')
    end
    assert_match(/curve/, error.message)
  end

  def test_ecdsa_point_must_be_uncompressed_65_bytes
    # 64 bytes (too short), 66 bytes (too long), and a compressed-form
    # prefix (0x03), which OpenSSH security keys do not use.
    ["\x04" + "\x00" * 63, "\x03" + "\x00" * 65, ""].each do |point|
      assert_raises(SK::SecurityKeyError) do
        SK::ECDSAPubKey.new('nistp256', point, 'ssh:')
      end
    end
  end

  def test_application_must_be_valid
    ["", "bad\0app", "\xff\xfe"].each do |application|
      assert_raises(SK::SecurityKeyError) { SK::PubKey.new(application) }
    end
  end

  def test_truncated_public_key_blob_is_rejected
    # Type name is intact but the following fields are truncated.
    [
      Net::SSH::Buffer.from(:string, SK::ED25519_TYPE, :string, ED_PUB),
      Net::SSH::Buffer.from(:string, SK::ECDSA_TYPE, :string, 'nistp256', :string, EC_POINT)
    ].each do |blob|
      assert_raises(StandardError) { Net::SSH::Buffer.new(blob).read_key }
    end
  end

  def test_public_key_blob_with_trailing_bytes_is_rejected
    [ED_PUBKEY_BLOB + 'X', EC_PUBKEY_BLOB + 'X'].each do |blob|
      assert_raises(SK::SecurityKeyError) { Net::SSH::Buffer.new(blob).read_key }
    end
  end

  def test_empty_inner_signature_is_rejected
    blob = SK.encode_signature_blob('ssh:', UP, 1, '')
    refute @ed_key.ssh_do_verify(blob, DATA, {})
  end

  def test_frozen_options_do_not_break_verification
    assert @ed_key.ssh_do_verify(ED_UP, DATA, {}.freeze)
  end

  def test_to_pem_roundtrip
    line = @ed_key.to_pem
    type, blob64 = line.split(' ', 2)
    assert_equal @ed_key.ssh_type, type
    assert_equal ED_PUBKEY_BLOB, Base64.decode64(blob64)
  end
end
