# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb/drb'
require_relative 'loopback_protocol'
require 'timeout'

# Tests for DRbServer's session front factory (:front_factory and
# :front_cleanup options).  A dedicated front object is created per
# accepted connection, objects exported by it are bound to the
# session, and the cleanup hook runs when the session ends.
class TestDRbSession < Test::Unit::TestCase
  class Document
    include DRb::DRbUndumped

    def initialize(name)
      @name = name
      @content = +''
    end

    def write(text)
      @content << text
    end

    def read
      @content
    end
  end

  class Workspace
    def initialize
      @id = object_id
      @store = {}
      @documents = {}
    end

    def session_id
      @id
    end

    def put(key, value)
      @store[key] = value
    end

    def get(key)
      @store[key]
    end

    def boom
      raise 'boom'
    end

    def open_document(name)
      @documents[name] ||= Document.new(name)
    end

    def document_count
      @documents.size
    end

    def document?(doc)
      @documents.value?(doc)
    end

    # Returns a document the workspace itself does not reference; only
    # the session's export table keeps it alive.
    def make_temp_document
      Document.new('temp')
    end

    def collect_garbage
      GC.start
      true
    end
  end

  # Stands in for the primary server so that client-side proxy
  # unmarshalling never resolves to local objects in this process.
  class NullPrimary
    def here?(uri)
      false
    end

    def config
      DRb::DRbServer.make_config
    end

    def uri
      'drbloop://null-primary'
    end

    def stop_service
    end
  end

  def setup
    @factory_sessions = []
    @cleanup_sessions = []
    @factory = lambda do |session|
      workspace = Workspace.new
      @factory_sessions << [session, workspace]
      workspace
    end
    @cleanup = lambda do |session|
      @cleanup_sessions << session
    end
    @uri = "drbloop://session-#{name}-#{object_id}"
    @server = new_session_server(@uri)
    # Keep client-side calls in this process honest: the server must
    # not be discoverable through DRb.fetch_server (used by
    # DRbObject.with_friend) nor be the primary server, so that
    # proxies are really marshalled instead of being resolved to
    # local objects.
    DRb.remove_server(@server)
    @previous_primary = DRb.primary_server
    DRb.primary_server = NullPrimary.new
  end

  def teardown
    @server.stop_service if @server && @server.alive?
    DRb.primary_server = @previous_primary
    DRb::DRbConn.stop_pool
  end

  private

  def new_session_server(uri, factory: @factory, cleanup: @cleanup)
    DRb::DRbServer.new(uri, nil,
                       :front_factory => factory,
                       :front_cleanup => cleanup)
  end

  # Two local clients.  Their URIs differ, so the client-side
  # connection pool gives each its own connection (its own session),
  # while both route to the same listener.
  def client_a
    DRb::DRbObject.new_with_uri(@uri)
  end

  def client_b
    DRb::DRbObject.new_with_uri("#{@uri}/b")
  end

  def factory_calls
    @factory_sessions.size
  end

  def cleanup_calls
    @cleanup_sessions.size
  end

  def wait_until
    Timeout.timeout(10) do
      sleep 0.01 until yield
    end
  end

  public

  def test_state_isolation_and_connection_reuse
    a = client_a
    a.put('theme', 'dark')
    assert_equal('dark', a.get('theme'))
    id_a = a.session_id
    assert_equal(id_a, a.session_id) # same connection, same front

    doc = a.open_document('memo')
    doc.write('hello')
    assert_equal('hello', doc.read)
    assert_equal(1, a.document_count)
    assert_equal(true, a.document?(doc)) # proxy round-trips to same object

    b = client_b
    assert_nil(b.get('theme')) # isolated from A's session
    assert_not_equal(id_a, b.session_id)

    assert_equal(2, factory_calls) # one factory call per connection
    assert_equal(0, cleanup_calls) # both sessions still alive

    assert_raise(RuntimeError) { a.boom }
    assert_raise(RuntimeError) { b.boom }
    wait_until { cleanup_calls == 2 }
    assert_equal(2, factory_calls)

    fronts = @cleanup_sessions.map(&:front)
    assert_equal(2, fronts.uniq.size)
    assert(fronts.all? { |front| Workspace === front })
  end

  def test_reconnect_after_connection_drop
    a = client_a
    a.put('key', 'value')
    id_before = a.session_id

    assert_raise(RuntimeError) { a.boom } # drops the connection
    wait_until { cleanup_calls == 1 }

    assert_nil(a.get('key')) # fresh session after reconnect
    assert_not_equal(id_before, a.session_id)
    assert_equal(2, factory_calls)

    assert_raise(RuntimeError) { a.boom }
    wait_until { cleanup_calls == 2 }
    assert_equal(2, factory_calls)
  end

  def test_child_objects_bound_to_session
    a = client_a
    doc = a.open_document('memo')
    doc.write('secret')
    ref = doc.__drbref

    # Another connection must not resolve A's exported object.
    forgery = DRb::DRbObject.new_with("#{@uri}/b", ref)
    assert_raise(RangeError) { forgery.read }

    # A's session is unaffected by the rejected probe.
    assert_equal('secret', doc.read)

    # Once A's session ends, the reference is revoked for good.
    assert_raise(RuntimeError) { a.boom }
    wait_until { cleanup_calls >= 2 }
    stale = DRb::DRbObject.new_with(@uri, ref)
    assert_raise(RangeError) { stale.read }

    wait_until { cleanup_calls == 3 }
    assert_equal(3, factory_calls)
  end

  def test_session_keeps_exported_objects_alive
    a = client_a
    doc = a.make_temp_document # referenced only by the session
    a.collect_garbage          # GC.start on the server side
    doc.write('still here')
    assert_equal('still here', doc.read)

    assert_raise(RuntimeError) { a.boom }
    wait_until { cleanup_calls == 1 }
    assert_equal(1, factory_calls)
  end

  def test_clean_disconnect_cleans_up_session
    conn = DRb::DRbProtocol.open(@uri, DRb.config)
    ref = DRb::DRbObject.new_with_uri(@uri)
    conn.send_request(ref, :put, ['key', 'value'], nil)
    assert_equal([true, 'value'], conn.recv_reply)
    conn.send_request(ref, :session_id, [], nil)
    succ, = conn.recv_reply
    assert_equal(true, succ)
    assert_equal(1, factory_calls)
    assert_equal(0, cleanup_calls)

    conn.close
    wait_until { cleanup_calls == 1 }
    assert_equal(1, factory_calls)
  end

  def test_factory_failure_leaves_nothing_registered
    attempts = []
    factory = lambda do |session|
      attempts << session
      raise 'factory broken' if attempts.size == 1
      Workspace.new
    end
    cleanups = []
    cleanup = ->(session) { cleanups << session }
    server = new_session_server("#{@uri}-fail",
                                :factory => factory, :cleanup => cleanup)
    begin
      client = DRb::DRbObject.new_with_uri(server.uri)
      assert_raise(DRb::DRbConnError) { client.get('key') }
      wait_until { attempts.size == 1 }
      assert_equal(0, cleanups.size) # no cleanup for a failed session
      assert(server.alive?)

      # The next connection gets a working session; nothing
      # half-registered interferes.
      assert_nil(client.get('key'))
      client.put('key', 'value')
      assert_equal('value', client.get('key'))
      wait_until { attempts.size == 2 }

      assert_raise(RuntimeError) { client.boom }
      wait_until { cleanups.size == 1 }
      assert_equal(2, attempts.size)
    ensure
      server.stop_service if server.alive?
    end
  end

  def test_cleanup_exception_does_not_prevent_close
    cleanups = []
    cleanup = lambda do |session|
      cleanups << session
      raise 'cleanup broken'
    end
    server = new_session_server("#{@uri}-cleanup", :cleanup => cleanup)
    begin
      a = DRb::DRbObject.new_with_uri(server.uri)
      a.put('key', 'value')
      assert_raise(RuntimeError) { a.boom }
      wait_until { cleanups.size == 1 }

      # The server is unaffected and keeps serving new sessions.
      b = DRb::DRbObject.new_with_uri("#{server.uri}/2")
      assert_nil(b.get('key'))
      assert_raise(RuntimeError) { b.boom }
      wait_until { cleanups.size == 2 }
      assert_equal(2, @factory_sessions.size)
    ensure
      server.stop_service if server.alive?
    end
  end

  def test_stop_service_stops_accepting_then_lets_sessions_finish
    a = client_a
    a.put('key', 'value')
    assert_equal(1, factory_calls)

    @server.stop_service
    assert(!@server.alive?)

    # New connections are refused.
    assert_raise(DRb::DRbConnError) { client_b.get('key') }

    # The in-flight session still completes per convention, and is
    # cleaned up when its connection ends.
    assert_equal('value', a.get('key'))
    assert_raise(RuntimeError) { a.boom }
    wait_until { cleanup_calls == 1 }
    assert_equal(1, factory_calls)
  end
end
