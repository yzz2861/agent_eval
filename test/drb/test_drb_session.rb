# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb/drb'

class TestDRbSession < Test::Unit::TestCase
  class Workspace
    include DRb::DRbUndumped

    def initialize(id, state = nil)
      @id = id
      @state = state
      @workspace = ChildWorkspace.new(id)
      @callback = nil
      @callback_thread = nil
    end

    attr_reader :id

    def workspace
      @workspace
    end

    def ping
      :pong
    end

    def start_callback(callback)
      @callback = callback
      @callback_thread = Thread.new { callback.wait(@id) }
      :started
    end

    def release_callback
      @callback&.release
    end
  end

  class ChildWorkspace
    include DRb::DRbUndumped

    def initialize(id)
      @id = id
    end

    attr_reader :id

    def ping
      :pong
    end
  end

  class CallbackClient
    include DRb::DRbUndumped

    def initialize
      @mutex = Mutex.new
      @waiting = nil
      @release = Queue.new
      @events = Queue.new
    end

    def wait(id)
      @mutex.synchronize { @waiting = id }
      @events.push([:waiting, id])
      @release.pop
      @events.push([:finished, id])
      :done
    end

    def release
      @release.push(true)
    end

    def pop_event
      @events.pop
    end
  end

  def teardown
    @servers&.each do |server|
      server.stop_service
      server.thread.join
    end
    DRb.stop_service
    DRb::DRbConn.stop_pool
  end

  def test_session_isolation_connection_reuse_and_reconnect
    factory_count = 0
    cleanup_count = 0
    mutex = Mutex.new
    server = start_session_server(
      front_factory: proc {
        mutex.synchronize { factory_count += 1 }
        Workspace.new(factory_count)
      },
      session_cleanup: proc {
        mutex.synchronize { cleanup_count += 1 }
      }
    )

    front1 = DRb::DRbObject.new_with_uri(server.uri)
    front2 = DRb::DRbObject.new_with_uri(server.uri)

    assert_equal(1, front1.id)
    assert_equal(2, front2.id)
    assert_equal(1, front1.id)
    assert_equal(2, front2.id)

    child1 = front1.workspace
    child2 = front2.workspace
    assert_equal(1, child1.id)
    assert_equal(2, child2.id)
    assert_equal(:pong, child1.ping)
    assert_equal(:pong, child2.ping)

    session1 = front1.instance_variable_get(:@client_session)
    session2 = front2.instance_variable_get(:@client_session)
    assert_not_same(session1, session2)
    assert_operator(session1.request_count, :>=, 3)
    connection = session1.connection
    assert_same(connection, session1.connection)

    stolen = DRb::DRbObject.new_with(front1.__drburi, child1.__drbref)
    error = assert_raise(DRb::DRbRemoteError) { stolen.ping }
    assert_match(/invalid session reference/, error.message)
    mutex.synchronize do
      assert_equal(3, factory_count)
      assert_equal(1, cleanup_count)
    end

    DRb.close_session(front1)
    assert(session1.closed?)
    assert_equal(4, front1.id)
    new_session1 = front1.instance_variable_get(:@client_session)
    assert_not_same(session1, new_session1)
    assert_equal(4, front1.workspace.id)
    assert_equal(2, front2.id)

    server.stop_service
    server.thread.join
    mutex.synchronize do
      assert_equal(4, factory_count)
      assert_equal(4, cleanup_count)
    end
  ensure
    server&.stop_service
  end

  def test_async_callback_is_retained_until_cleanup_completes_it
    cleanup_events = Queue.new
    server = start_session_server(
      front_factory: proc { Workspace.new(:workspace) },
      session_cleanup: proc do |front|
        cleanup_events.push(:cleanup_started)
        front.release_callback
      end
    )

    front = DRb::DRbObject.new_with_uri(server.uri)
    callback = CallbackClient.new
    assert_equal(:started, front.start_callback(callback))
    assert_equal([:waiting, :workspace], callback.pop_event)

    DRb.close_session(front)
    assert_equal(:cleanup_started, cleanup_events.pop)
    assert_equal([:finished, :workspace], callback.pop_event)

    server.stop_service
    server.thread.join
  ensure
    server&.stop_service
  end

  def test_factory_failure_does_not_register_or_clean_session
    attempts = 0
    cleanups = 0
    mutex = Mutex.new
    server = start_session_server(
      front_factory: proc do
        mutex.synchronize { attempts += 1 }
        raise RuntimeError, 'factory unavailable' if attempts == 1
        Workspace.new(attempts)
      end,
      session_cleanup: proc { mutex.synchronize { cleanups += 1 } }
    )

    front = DRb::DRbObject.new_with_uri(server.uri)
    assert_raise(DRb::DRbConnError) { front.ping }
    assert_equal(:pong, front.ping)

    server.stop_service
    server.thread.join
    mutex.synchronize do
      assert_equal(2, attempts)
      assert_equal(1, cleanups)
    end
  ensure
    server&.stop_service
  end

  def test_cleanup_error_still_closes_socket
    cleanups = 0
    mutex = Mutex.new
    server = start_session_server(
      front_factory: proc { Workspace.new(:workspace) },
      session_cleanup: proc do
        mutex.synchronize { cleanups += 1 }
        raise RuntimeError, 'cleanup failed'
      end
    )

    front = DRb::DRbObject.new_with_uri(server.uri)
    assert_equal(:pong, front.ping)
    DRb.close_session(front)
    assert_equal(:pong, front.ping)

    server.stop_service
    server.thread.join
    assert_equal(2, mutex.synchronize { cleanups })
  ensure
    server&.stop_service
  end

  private

  def start_session_server(front_factory:, session_cleanup:)
    server = DRb::DRbServer.new(
      'druby://localhost:0',
      nil,
      front_factory: front_factory,
      session_cleanup: session_cleanup,
      session_shutdown_timeout: 5
    )
    @servers ||= []
    @servers << server
    server
  end

end
