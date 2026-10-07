# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb/drb'
require 'socket'
require 'timeout'

module DRbTests

class TestDRbBidi < Test::Unit::TestCase

  # Server-side object at the deepest end of the example calls.
  class Service
    include DRb::DRbUndumped

    def middle_call(middle, callback)
      middle.run(self, callback)
    end

    def inspect_args(*args)
      args
    end

    def ping(value)
      "pong:#{value}"
    end

    # Sleeps until released; used by the disconnect test.
    def hang(release)
      @queue ||= Thread::Queue.new
      release.signal_session
      @queue.pop
      'never'
    end
  end

  # Lives on the client side, reached through the reverse direction of the
  # session (the server cannot connect to it directly).
  class Callback
    include DRb::DRbUndumped

    def level3(service_proxy)
      service_proxy.ping(7)
    end

    def signal_session
      # handled by the disconnect test through a specialized subclass
    end
  end

  # Lives on the client side but is passed to the server; while the client
  # thread is blocked inside the server call the server invokes #run back
  # over the same socket, and #run calls the server again over the same
  # socket (re-entrant call while a reply is pending).
  class Middle
    include DRb::DRbUndumped

    def run(service_proxy, callback)
      echoed = service_proxy.ping(3)
      inner = callback.level3(service_proxy)
      "middle:#{echoed}:#{inner}"
    end
  end

  def setup
    # The passive server is started first so it becomes the primary server
    # of the client process.  It does not listen on any port at all.
    @passive = DRb::DRbServer.new('drbvbidi:', nil, bidi: true)
    begin
      @listener = DRb::DRbServer.new('druby://127.0.0.1:0', Service.new, bidi: true)
      # Connect through a different name so the reference is not short
      # circuited in-process via DRb.here?; it must travel over the wire.
      _, port, = DRb::DRbTCPSocket.send(:parse_uri, @listener.uri)
      @remote_uri = "druby://localhost:#{port}"
    rescue Errno::EPERM, Errno::EACCES
      # Sandbox forbids binding: exercise the exact same session logic over
      # a connected socket pair instead of a real TCP listener.
      @socketpair = true
      @listener = build_socketpair_listener(Service.new)
      @remote_uri = @listener.uri
    end
    @remote = DRb::DRbObject.new_with_uri(@remote_uri)
  end

  class ParkedListener
    def initialize(uri)
      @uri = uri
      @r, @w = IO.pipe
    end
    attr_reader :uri
    def accept
      IO.select([@r])
      nil
    end
    def shutdown
      @w.close unless @w.closed?
    end
    def close
      [@r, @w].each { |io| io.close unless io.closed? }
    end
  end

  # Build a bidi-enabled server that owns the server side of a socket pair,
  # plus a bidi transport connected to the other end.  The session itself
  # is identical to the TCP case; only the establishment differs.
  private def build_socketpair_listener(front)
    uri = 'druby://127.0.0.1:1'
    parked = ParkedListener.new(uri)
    protocol_module = DRb::DRbProtocol
    original = protocol_module.method(:open_server)
    protocol_module.singleton_class.send(:define_method, :open_server) do |u, c, f=true|
      parked
    end
    begin
      server = DRb::DRbServer.new(uri, front, bidi: true)
    ensure
      protocol_module.singleton_class.send(:define_method, :open_server, original)
    end
    a, b = Socket.pair(:UNIX, :STREAM)
    server_side = DRb::DRbTCPSocket.new(uri, a, server.config)
    Thread.start { server_side.bidi_upgrade(server) }
    client_side = DRb::DRbTCPSocket.new(uri, b, @passive.config)
    DRb::DRbBidiProtocol.start_bidi_client(client_side, @passive.config)
    # Keep both ends reachable from GC for the life of the test.
    @socketpair_transports = [server_side, client_side]
    server
  end

  def teardown
    @listener&.stop_service
    @passive&.stop_service
    DRb::DRbConn.stop_pool
  end

  private def single_session
    # In-process tests contain both ends of the same connection; only the
    # client side is a session this process initiates calls through.
    sessions = DRb::DRbBidiProtocol.client_sessions
    unique = sessions.values.uniq
    unless unique.size == 1
      raise "expected one session, got #{unique.size}: #{sessions.keys.inspect}"
    end
    unique.first
  end

  def test_single_listening_port
    passive_protocol = @passive.instance_variable_get(:@protocol)
    assert_kind_of DRb::DRbBidiListener, passive_protocol
    assert_equal 'drbvbidi:', passive_protocol.uri
    # The passive transport never binds or accepts a socket.
    assert !passive_protocol.respond_to?(:stream)
  end

  def test_basic_callback_over_session
    result = @remote.ping(11)
    assert_equal 'pong:11', result

    callback = Callback.new
    result = @remote.inspect_args(1, 'two', callback)
    assert_equal [1, 'two'], result.first(2)
    # Cross-process it arrives as a DRbObject; in-process _load resolves it
    # to the original object, exactly like classic DRb.
    assert(result.last.is_a?(DRb::DRbObject) || result.last.is_a?(Callback))

    result = @remote.middle_call(Middle.new, Callback.new)
    assert_equal 'middle:pong:3:pong:7', result
    single_session
  end

  def test_three_level_nested_call
    callback = Object.new
    callback.extend(DRb::DRbUndumped)
    def callback.level3(service)
      service.ping(7)
    end
    middle = Object.new
    middle.extend(DRb::DRbUndumped)
    middle.define_singleton_method(:run) do |service, cb|
      first = service.ping(2)
      second = cb.level3(service)
      "#{first}:#{second}"
    end

    result = @remote.middle_call(middle, callback)
    assert_equal 'pong:2:pong:7', result
    single_session
  end

  def test_callback_exception_reaches_correct_layer
    callback = Object.new
    callback.extend(DRb::DRbUndumped)
    def callback.level3(service)
      raise ArgumentError, 'boom at callback'
    end
    middle = Middle.new
    error = assert_raise(ArgumentError) do
      @remote.middle_call(middle, callback)
    end
    assert_equal 'boom at callback', error.message
    single_session
  end

  def test_two_concurrent_requests_share_one_socket
    results = Array.new(2)
    threads = 2.times.map do |i|
      Thread.start do
        results[i] = @remote.ping(i)
      end
    end
    threads.each(&:join)
    assert_equal ['pong:0', 'pong:1'], results
    single_session
  end

  def test_two_concurrent_nested_calls
    threads = 2.times.map do |i|
      Thread.start do
        cb = Callback.new
        def cb.level3(service)
          service.ping(100)
        end
        @remote.middle_call(Middle.new, cb)
      end
    end
    values = threads.map { |t| t.value }
    assert_equal ['middle:pong:3:pong:100'] * 2, values
    single_session
  end

  class DisconnectingCallback < Callback
    def initialize(server_uri)
      @server_uri = server_uri
    end

    def signal_session
      session = DRb::DRbBidiProtocol.lookup(@server_uri)
      Thread.start do
        sleep 0.1
        session.close
      end
    end
  end

  def test_disconnect_wakes_all_waiters
    # Prime the session before spawning the blocked calls.
    assert_equal 'pong:prime', @remote.ping('prime')
    session = single_session
    errors = []
    threads = 2.times.map do
      Thread.start do
        begin
        @remote.hang(DisconnectingCallback.new(@remote_uri))
        rescue DRb::DRbConnError => e
          errors << e
        end
      end
    end

    Thread.pass until errors.size == 2 || !threads.all?(&:alive?)
    Timeout.timeout(10) { threads.each(&:join) }
    assert_equal 2, errors.size
    assert(errors.all? { |e| e.message == 'connection closed' })
    assert !session.alive?
    unless @socketpair
      # The registry removes the closed session; subsequent calls establish
      # a fresh connection instead of reusing the dead one.
      assert_equal 'pong:reborn', @remote.ping('reborn')
    end
  end

  def test_bidi_client_rejected_by_classic_server
    if @socketpair
      a, b = Socket.pair(:UNIX, :STREAM)
      classic_server = build_classic_socketpair_server(a)
      server_side = DRb::DRbTCPSocket.new('druby://127.0.0.1:2', a, classic_server.config)
      Thread.start { server_side.bidi_upgrade(classic_server) }
      error = assert_raise(DRb::DRbConnError) do
        client_side = DRb::DRbTCPSocket.new('druby://127.0.0.1:2', b, @passive.config)
        DRb::DRbBidiProtocol.start_bidi_client(client_side, @passive.config)
      end
      assert_match(/bidirectional/, error.message)
      b.close
      classic_server.stop_service
    else
      classic = DRb::DRbServer.new('druby://127.0.0.1:0', Object.new, bidi: false)
      _, port, = DRb::DRbTCPSocket.send(:parse_uri, classic.uri)
      remote = DRb::DRbObject.new_with_uri("druby://localhost:#{port}")
      error = assert_raise(DRb::DRbConnError) do
        remote.ping(1)
      end
      assert_match(/bidirectional/, error.message)
      classic.stop_service
    end
  end

  def test_bidi_handshake_rejects_bad_version
    a, b = Socket.pair(:UNIX, :STREAM)
    parked = ParkedListener.new('druby://127.0.0.1:3')
    protocol_module = DRb::DRbProtocol
    original = protocol_module.method(:open_server)
    protocol_module.singleton_class.send(:define_method, :open_server) { |u, c, f=true| parked }
    server = DRb::DRbServer.new('druby://127.0.0.1:3', Service.new, bidi: true)
    protocol_module.singleton_class.send(:define_method, :open_server, original)
    server_side = DRb::DRbTCPSocket.new('druby://127.0.0.1:3', a, server.config)
    Thread.start { server_side.bidi_upgrade(server) }

    client_side = DRb::DRbTCPSocket.new('druby://127.0.0.1:3', b, @passive.config)
    hello = DRb::DRbBidiProtocol::HANDSHAKE_MAGIC + [99].pack('C') + "\x00\x00\x00\x00".b
    client_side.stream.write(hello)
    reply = b.read(14)
    status = reply.getbyte(DRb::DRbBidiProtocol::HANDSHAKE_MAGIC.bytesize + 1)
    assert_equal DRb::DRbBidiProtocol::HANDSHAKE_BAD_VERSION, status
    client_side.close
    server.stop_service
  end

  def test_classic_client_still_accepted
    if @socketpair
      a, b = Socket.pair(:UNIX, :STREAM)
      @classic_server = build_classic_socketpair_server(a)
      @classic_socket = a
      transport = DRb::DRbTCPSocket.new('druby://127.0.0.1:2', b, DRb::DRbServer.make_config(bidi: false))
      @classic_thread = Thread.start do
        client = DRb::DRbTCPSocket.new('druby://127.0.0.1:2', a, @classic_server.config)
        Thread.current['DRb'] = { 'client' => client, 'server' => @classic_server }
        succ, result = DRb::DRbServer::InvokeMethod.new(@classic_server, client).perform
        client.send_reply(succ, result)
      end
      null_ref = Object.new
      def null_ref.__drbref; nil; end
      transport.send_request(null_ref, :ping, [1], nil)
      succ, result = transport.recv_reply
      assert_equal(true, succ, "classic request failed: #{result.class}: #{result.inspect}")
      assert_equal 'pong:1', result
      transport.close
      @classic_thread.join
      @classic_server.stop_service
    else
      classic_config = DRb::DRbServer.make_config(bidi: false)
      protocol = DRb::DRbProtocol.open(@remote_uri, classic_config)
      begin
        null_ref = Object.new
        def null_ref.__drbref; nil; end
        protocol.send_request(null_ref, :ping, [1], nil)
        succ, result = protocol.recv_reply
        assert succ
        assert_equal 'pong:1', result
      ensure
        protocol.close
      end
    end
  end

  # A classic (non-bidi) server attached to one socket-pair end.  For the
  # rejection case its listener runs bidi_upgrade (which answers
  # UNSUPPORTED); for the classic-accept case it runs the classic loop.
  def build_classic_socketpair_server(socket)
    uri = 'druby://127.0.0.1:2'
    parked = ParkedListener.new(uri)
    protocol_module = DRb::DRbProtocol
    original = protocol_module.method(:open_server)
    protocol_module.singleton_class.send(:define_method, :open_server) { |u, c, f=true| parked }
    server = DRb::DRbServer.new(uri, Service.new, bidi: false)
    protocol_module.singleton_class.send(:define_method, :open_server, original)
    server
  end
end

end
