require_relative '../common'
require 'net/ssh'
require 'tempfile'

module NetSSH
  class TestCanonicalizationStart < NetSSHTest
    def setup
      authentication_session = mock('authentication_session')
      authentication_session.stubs(:authenticate).returns(true)
      Net::SSH::Authentication::Session.stubs(:new).returns(authentication_session)
      @transport_session = mock('transport_session')
      Net::SSH::Transport::Session.stubs(:new).returns(@transport_session)
      @connection_session = mock('connection_session')
      Net::SSH::Connection::Session.stubs(:new).returns(@connection_session)
      @config_file = Tempfile.create('ssh_config')
      @config_file.write(<<~CONFIG)
        Host *
          CanonicalizeHostname yes
          CanonicalDomains example.com
          CanonicalizeFallbackLocal no
          User configuser
      CONFIG
      @config_file.close
    end

    def teardown
      File.unlink(@config_file.path) if File.exist?(@config_file.path)
    end

    def test_start_connects_to_canonical_host_using_injected_resolver
      resolver = Class.new do
        def self.resolve(host)
          host == 'box.example.com' ? 'box.example.com' : nil
        end
      end

      connected_host = nil
      Net::SSH::Transport::Session.stubs(:new).with do |host, _options|
        connected_host = host
        @transport_session
      end
      @connection_session.stubs(:closed?).returns(true)

      Net::SSH.start('box', nil, config: @config_file.path, canonicalize_resolver: resolver)

      assert_equal 'box.example.com', connected_host
    end

    def test_explicit_start_host_name_overrides_canonical_name
      resolver = stub('resolver')
      resolver.stubs(:resolve).returns('box.example.com')
      @connection_session.stubs(:closed?).returns(true)

      connected_host = nil
      Net::SSH::Transport::Session.stubs(:new).with do |host, _options|
        connected_host = host
        @transport_session
      end

      Net::SSH.start('box', nil,
                     config: @config_file.path,
                     canonicalize_resolver: resolver,
                     host_name: 'explicit.example.net')

      assert_equal 'explicit.example.net', connected_host
    end
  end
end
