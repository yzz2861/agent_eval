# frozen_string_literal: true

require 'net/smtp'
require 'stringio'
require 'test/unit'

module Net
  class TestSMTPAuthScramSHA256 < Test::Unit::TestCase
    CNONCE = 'rOprNGaxhTBaTXFZUm-MugrLHQqD1YevNz4rDttjeT4'
    SERVER_NONCE = CNONCE + '36pS'
    CLIENT_PROOF = '1aJwa05ub6Hlt+wz1n0dutwosvWLGAdt8qC/6wpxbjU='
    SERVER_SIGNATURE = '2/iWfyEJF6rf6UigxwHsY1+zES637sx+LFMl28vJMTY='
    SALT = 'W22ZaJ0SNY7soEsUEjb6gQ=='
    SALTED_PASSWORD = 'c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d'

    def test_rfc7677_test_vector_and_empty_final_confirmation
      server = PseudoSMTPServer.new(
        continuation(server_first),
        continuation("v=#{SERVER_SIGNATURE}"),
        success
      )
      response = authenticator(server).auth('user', 'pencil')

      assert_predicate response, :success?
      assert_equal expected_initial_command, server.commands[0]
      assert_equal expected_client_final_command, server.commands[1]
      assert_equal '', server.commands[2]
    end

    def test_username_special_characters_are_sasl_encoded
      server = PseudoSMTPServer.new(
        continuation(server_first.sub(SERVER_NONCE, CNONCE)),
        continuation('e=other-error'),
        success
      )
      auth = authenticator(server)
      begin
        auth.auth('user,name=value', 'pencil')
      rescue Net::SMTPAuthenticationError
      end

      encoded_client_first = server.commands.first.split(' ', 3).last
      assert_include encoded_client_first.unpack1('m0'), 'n=user=2Cname=3Dvalue'
    end

    def test_rfc7677_salted_password_vector
      authenticator = Net::SMTP::AuthScramSHA256.allocate
      authenticator.instance_variable_set(:@password, 'pencil')
      authenticator.instance_variable_set(:@salt, SALT.unpack1('m0'))
      authenticator.instance_variable_set(:@iterations, 4096)

      assert_equal SALTED_PASSWORD, authenticator.send(:salted_password).unpack1('H*')
    end

    def test_rejects_bad_server_signature
      server = PseudoSMTPServer.new(
        continuation(server_first),
        continuation('v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
        success
      )

      error = assert_raise(Net::SMTPAuthenticationError) do
        authenticator(server).auth('user', 'pencil')
      end
      assert_equal 'SCRAM-SHA-256 authentication failed', error.message
    end

    def test_rejects_server_error_attribute
      server = PseudoSMTPServer.new(
        continuation(server_first),
        continuation('e=invalid-encoding'),
        success
      )

      assert_raise(Net::SMTPAuthenticationError) do
        authenticator(server).auth('user', 'pencil')
      end
    end

    def test_rejects_missing_and_invalid_base64_server_verifier
      reject_server_final('e=invalid-encoding,v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
      reject_server_final('v=not-base64!')
      reject_server_final('v=')
    end

    def test_rejects_success_status_without_server_final_message
      server = PseudoSMTPServer.new(continuation(server_first), success)

      assert_raise(Net::SMTPUnknownError) do
        authenticator(server).auth('user', 'pencil')
      end
    end

    def test_rejects_duplicate_attributes
      reject_server_first("r=#{CNONCE},r=#{CNONCE},s=#{SALT},i=4096")
      reject_server_first("r=#{CNONCE},s=#{SALT},s=#{SALT},i=4096")
      reject_server_first("r=#{CNONCE},s=#{SALT},i=4096,i=4097")
      reject_server_first("r=#{CNONCE},r=other,s=#{SALT},i=4096")
    end

    def test_rejects_invalid_base64_and_iteration_counts
      reject_server_first("r=#{CNONCE},s=not-base64!,i=4096")
      reject_server_first("r=#{CNONCE},s=#{SALT},i=4095")
      reject_server_first("r=#{CNONCE},s=#{SALT},i=04096")
      reject_server_first("r=#{CNONCE},s=#{SALT},i=1048577")
      reject_server_first("r=#{CNONCE},s=#{SALT},i=#{'9' * 100}")
    end

    def test_rejects_unexpected_attributes_missing_attributes_and_wrong_order
      reject_server_first("m=extension,r=#{CNONCE},s=#{SALT},i=4096")
      reject_server_first("i=4096,r=#{CNONCE},s=#{SALT}")
      reject_server_first("r=#{CNONCE},s=#{SALT}")
    end

    def test_rejects_nonce_without_client_contribution_prefix
      reject_server_first('r=different,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096')
    end

    def test_debug_output_omits_authentication_exchange
      debug_io = DebugIO.new
      server = PseudoSMTPServer.new(
        continuation(server_first),
        continuation('v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
        success
      )
      server.socket = debug_io

      assert_raise(Net::SMTPAuthenticationError) do
        authenticator(server).auth('user', 'pencil')
      end

      assert_empty debug_io.debug_output.string
    end

    def test_generated_client_nonce_is_present_and_unique
      first_client_nonce
      second_client_nonce

      assert_equal 24, first_client_nonce.length
      assert_match(/\A[A-Za-z0-9_-]+\z/, first_client_nonce)
      assert_not_equal first_client_nonce, second_client_nonce
    end

    private

    def authenticator(server)
      authenticator = Net::SMTP::AuthScramSHA256.new(server)
      authenticator.instance_variable_set(:@client_nonce, CNONCE)
      authenticator
    end

    def first_client_nonce
      @first_client_nonce ||= begin
        server = PseudoSMTPServer.new
        auth = Net::SMTP::AuthScramSHA256.new(server)
        auth.send(:generate_client_nonce)
      end
    end

    def second_client_nonce
      @second_client_nonce ||= begin
        server = PseudoSMTPServer.new
        auth = Net::SMTP::AuthScramSHA256.new(server)
        auth.send(:generate_client_nonce)
      end
    end

    def reject_server_first(message)
      server = PseudoSMTPServer.new(continuation(message), success)
      assert_raise(Net::SMTPAuthenticationError) do
        authenticator(server).auth('user', 'pencil')
      end
    end

    def reject_server_final(message)
      server = PseudoSMTPServer.new(
        continuation(server_first),
        continuation(message),
        success
      )
      assert_raise(Net::SMTPAuthenticationError) do
        authenticator(server).auth('user', 'pencil')
      end
    end

    def continuation(message)
      Net::SMTP::Response.new('334', "334 #{[message].pack('m0')}")
    end

    def success
      Net::SMTP::Response.new('235', '235 2.7.0 Authentication successful')
    end

    def server_first
      "r=#{SERVER_NONCE},s=#{SALT},i=4096"
    end

    def expected_initial_command
      "AUTH SCRAM-SHA-256 #{['n,,n=user,r=' + CNONCE].pack('m0')}"
    end

    def expected_client_final_command
      ["c=biws,r=#{SERVER_NONCE},p=#{CLIENT_PROOF}"].pack('m0')
    end

    class PseudoSMTPServer
      attr_reader :commands
      attr_accessor :socket

      def initialize(*responses)
        @responses = responses
        @commands = []
      end

      def get_response(command)
        @commands << command
        response = @responses.shift
        raise 'missing pseudo-server response' unless response
        response
      end
    end

    class DebugIO
      attr_reader :debug_output

      def initialize
        @debug_output = StringIO.new
      end

      def debug_output=(value)
        @debug_output = value
      end
    end
  end
end
