require_relative '../common'
require 'net/ssh/test'
require 'net/ssh/authentication/session'

module Authentication
  # Exercises RFC 8308 EXT_INFO / server-sig-algs handling end to end,
  # using the scripted transport (Net::SSH::Test) so that the exact
  # algorithm names sent in the USERAUTH_REQUEST packets can be verified.
  class TestExtInfo < NetSSHTest
    include Net::SSH::Test
    include Net::SSH::Authentication::Constants

    def test_server_sig_algs_sha2_only_authenticates_with_sha2
      story do |script|
        script_service_request(script, ext_info_payload(['server-sig-algs', 'rsa-sha2-512,rsa-sha2-256']))
        script_publickey_auth(script, 'rsa-sha2-512')
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_equal %w[rsa-sha2-512 rsa-sha2-256], transport.algorithms.server_signature_algorithms
    end

    def test_without_ext_info_falls_back_to_default_algorithms
      story do |script|
        script.sends(:service_request, 'ssh-userauth')
        script.gets(:service_accept, 'ssh-userauth')
        # the default preferences are tried in order until one succeeds
        script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', false, 'rsa-sha2-512', key_blob)
        script.gets(:userauth_failure, 'publickey', false)
        script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', false, 'rsa-sha2-256', key_blob)
        script.gets(:userauth_failure, 'publickey', false)
        script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', false, 'ssh-rsa', key_blob)
        script.gets(:userauth_pk_ok, 'ssh-rsa', key_blob)
        script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', true, 'ssh-rsa', key_blob, nil)
        script.gets(:userauth_success)
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_nil transport.algorithms.server_signature_algorithms
    end

    def test_ext_info_received_before_newkeys_is_ignored
      # inject an EXT_INFO into the middle of the initial key exchange;
      # it arrives before NEWKEYS, which is not a valid phase for it
      socket.script.events.insert(
        3, Net::SSH::Test::RemotePacket.new(:ext_info, ext_info_payload(['server-sig-algs', 'ssh-rsa']))
      )

      story do |script|
        script_service_request(script, ext_info_payload(['server-sig-algs', 'rsa-sha2-512,rsa-sha2-256']))
        script_publickey_auth(script, 'rsa-sha2-512')
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_equal %w[rsa-sha2-512 rsa-sha2-256], transport.algorithms.server_signature_algorithms
    end

    def test_duplicate_ext_info_is_ignored
      story do |script|
        # a second EXT_INFO must not replace the policy established by the first
        script_service_request(
          script,
          ext_info_payload(['server-sig-algs', 'rsa-sha2-512,rsa-sha2-256']),
          ext_info_payload(['server-sig-algs', 'ssh-rsa'])
        )
        script_publickey_auth(script, 'rsa-sha2-512')
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_equal %w[rsa-sha2-512 rsa-sha2-256], transport.algorithms.server_signature_algorithms
    end

    def test_late_ext_info_is_ignored
      story do |script|
        script.sends(:service_request, 'ssh-userauth')
        script.gets(:service_accept, 'ssh-userauth')
        script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', false, 'rsa-sha2-512', key_blob)
        # arrives long after NEWKEYS, once regular traffic has started
        script.gets(:ext_info, ext_info_payload(['server-sig-algs', 'ssh-rsa']))
        script.gets(:userauth_pk_ok, 'rsa-sha2-512', key_blob)
        script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', true, 'rsa-sha2-512', key_blob, nil)
        script.gets(:userauth_success)
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_nil transport.algorithms.server_signature_algorithms
    end

    def test_ext_info_with_excessive_extension_count_is_ignored
      payload = Net::SSH::Buffer.from(
        :long, 100,
        :string, 'server-sig-algs', :string, 'ssh-rsa'
      ).to_s

      story do |script|
        script_service_request(script, payload)
        script_publickey_auth(script, 'rsa-sha2-512')
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_nil transport.algorithms.server_signature_algorithms
    end

    def test_ext_info_with_truncated_extension_is_ignored
      # the declared value length runs past the end of the packet; a parser
      # that trusted it would install a truncated "ssh-rsa"-only policy
      payload = Net::SSH::Buffer.from(
        :long, 1,
        :long, 15, :raw, 'server-sig-algs',
        :long, 100, :raw, 'ssh-rsa'
      ).to_s

      story do |script|
        script_service_request(script, payload)
        script_publickey_auth(script, 'rsa-sha2-512')
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_nil transport.algorithms.server_signature_algorithms
    end

    def test_ext_info_with_duplicate_extension_names_is_ignored
      payload = ext_info_payload(
        ['server-sig-algs', 'ssh-rsa'],
        ['server-sig-algs', 'rsa-sha2-512,rsa-sha2-256']
      )

      story do |script|
        script_service_request(script, payload)
        script_publickey_auth(script, 'rsa-sha2-512')
      end

      assert_scripted do
        assert auth_session.authenticate('ssh-connection', 'jamis')
      end
      assert_nil transport.algorithms.server_signature_algorithms
    end

    def test_server_sig_algs_without_common_algorithm_raises_with_reason
      story do |script|
        script_service_request(script, ext_info_payload(['server-sig-algs', 'ssh-ed25519']))
      end

      assert_scripted do
        error = assert_raises(Net::SSH::Exception) do
          auth_session.authenticate('ssh-connection', 'jamis')
        end
        assert_match(/server-sig-algs: ssh-ed25519/, error.message)
      end
    end

    private

    def self.rsa_key
      @rsa_key ||= OpenSSL::PKey::RSA.new(2048)
    end

    def rsa_key
      self.class.rsa_key
    end

    def key_blob
      Net::SSH::Buffer.from(:key, rsa_key).to_s
    end

    def auth_session
      @auth_session ||= Net::SSH::Authentication::Session.new(
        transport,
        auth_methods: %w[publickey],
        key_data: [rsa_key.to_pem]
      )
    end

    # Builds the raw payload of an EXT_INFO packet from [name, value] pairs.
    def ext_info_payload(*extensions)
      buffer = Net::SSH::Buffer.new
      buffer.write_long(extensions.length)
      extensions.each do |name, value|
        buffer.write_string(name)
        buffer.write_string(value)
      end
      buffer.to_s
    end

    # Scripts the client service request, after which the server sends any
    # EXT_INFO packets (they are only valid right after NEWKEYS, and are
    # picked up by the client on its first read) and its service accept.
    def script_service_request(script, *ext_info_payloads)
      script.sends(:service_request, 'ssh-userauth')
      ext_info_payloads.each { |payload| script.gets(:ext_info, payload) }
      script.gets(:service_accept, 'ssh-userauth')
    end

    # Scripts a complete publickey authentication exchange in which the
    # client must offer and sign with the given algorithm name.
    def script_publickey_auth(script, alg)
      script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', false, alg, key_blob)
      script.gets(:userauth_pk_ok, alg, key_blob)
      script.sends(:userauth_request, 'jamis', 'ssh-connection', 'publickey', true, alg, key_blob, nil)
      script.gets(:userauth_success)
    end
  end
end
