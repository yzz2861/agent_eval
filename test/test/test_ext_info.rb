require_relative '../common'
require 'net/ssh/test'
require 'net/ssh/authentication/session'

# Exercises RFC 8308 extension negotiation (EXT_INFO / server-sig-algs)
# through a fully scripted transport, verifying the signature algorithm
# names the client actually puts on the wire during publickey auth.
class TestExtInfo < NetSSHTest
  include Net::SSH::Test
  include Net::SSH::Transport::Constants
  include Net::SSH::Authentication::Constants

  def setup
    @server_kex = "test"
  end

  def test_server_sig_algs_selects_sha2_signature_for_rsa_key
    @server_kex = "test,ext-info-s"

    story do |script|
      script.sends(:service_request, "ssh-userauth")
      script.gets(:ext_info, 1, "server-sig-algs", "rsa-sha2-512,rsa-sha2-256")
      script.gets(:service_accept, "ssh-userauth")
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-512")
      script.gets(:userauth_failure, "publickey", false)
      # the next attempt must be the other SHA-2 algorithm, never ssh-rsa
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-256")
      script.gets(:userauth_pk_ok, "rsa-sha2-256", key_blob)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", true, "rsa-sha2-256")
      script.gets(:userauth_success)
    end

    assert_scripted do
      assert auth_session.authenticate("ssh-connection", "jamis")
    end
    assert_equal %w[rsa-sha2-512 rsa-sha2-256], transport.algorithms.server_sig_algs
  end

  def test_without_ext_info_falls_back_to_trying_each_signature_algorithm
    story do |script|
      script.sends(:service_request, "ssh-userauth")
      script.gets(:service_accept, "ssh-userauth")
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-512")
      script.gets(:userauth_failure, "publickey", false)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-256")
      script.gets(:userauth_failure, "publickey", false)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "ssh-rsa")
      script.gets(:userauth_pk_ok, "ssh-rsa", key_blob)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", true, "ssh-rsa")
      script.gets(:userauth_success)
    end

    assert_scripted do
      assert auth_session.authenticate("ssh-connection", "jamis")
    end
    assert_nil transport.algorithms.server_sig_algs
  end

  def test_duplicate_ext_info_message_does_not_change_auth_policy
    @server_kex = "test,ext-info-s"

    story do |script|
      script.sends(:service_request, "ssh-userauth")
      script.gets(:ext_info, 1, "server-sig-algs", "rsa-sha2-512,rsa-sha2-256")
      # a second EXT_INFO is out of phase and must be ignored
      script.gets(:ext_info, 1, "server-sig-algs", "ssh-rsa")
      script.gets(:service_accept, "ssh-userauth")
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-512")
      script.gets(:userauth_pk_ok, "rsa-sha2-512", key_blob)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", true, "rsa-sha2-512")
      script.gets(:userauth_success)
    end

    assert_scripted do
      assert auth_session.authenticate("ssh-connection", "jamis")
    end
    assert_equal %w[rsa-sha2-512 rsa-sha2-256], transport.algorithms.server_sig_algs
  end

  def test_ext_info_without_ext_info_s_advertisement_is_ignored
    # the server never announced ext-info-s, so the packet is out of phase
    # and the legacy trial-and-error behavior must be kept
    story do |script|
      script.sends(:service_request, "ssh-userauth")
      script.gets(:ext_info, 1, "server-sig-algs", "ssh-rsa")
      script.gets(:service_accept, "ssh-userauth")
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-512")
      script.gets(:userauth_failure, "publickey", false)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "rsa-sha2-256")
      script.gets(:userauth_failure, "publickey", false)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", false, "ssh-rsa")
      script.gets(:userauth_pk_ok, "ssh-rsa", key_blob)
      script.sends(:userauth_request, "jamis", "ssh-connection", "publickey", true, "ssh-rsa")
      script.gets(:userauth_success)
    end

    assert_scripted do
      assert auth_session.authenticate("ssh-connection", "jamis")
    end
    assert_nil transport.algorithms.server_sig_algs
  end

  def test_server_sig_algs_without_common_algorithm_raises_with_reason
    @server_kex = "test,ext-info-s"

    story do |script|
      script.sends(:service_request, "ssh-userauth")
      script.gets(:ext_info, 1, "server-sig-algs", "ssh-ed25519")
      script.gets(:service_accept, "ssh-userauth")
    end

    assert_scripted do
      error = assert_raises(Net::SSH::Exception) do
        auth_session.authenticate("ssh-connection", "jamis")
      end
      assert_match(/could not settle on publickey signature algorithm/, error.message)
      assert_match(/ssh-ed25519/, error.message)
    end
  end

  private

  def socket(options = {})
    @socket ||= Net::SSH::Test::Socket.new(server_kex: @server_kex)
  end

  def auth_session
    @auth_session ||= Net::SSH::Authentication::Session.new(
      transport,
      auth_methods: %w[publickey],
      use_agent: false,
      non_interactive: true,
      key_data: [private_key]
    )
  end

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.new(2048).to_pem
  end

  def public_key
    @public_key ||= OpenSSL::PKey::RSA.new(private_key)
  end

  def key_blob
    Net::SSH::Buffer.from(:key, public_key).to_s
  end
end
