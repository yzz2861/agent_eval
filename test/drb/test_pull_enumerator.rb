require_relative '../lib/helper'
require 'drb/drb'
require 'drb/pull_enumerator'
require 'drb/unix'
require 'tmpdir'

module PullEnumeratorTests
  # A lazy generator whose ensure block records that its resource was
  # released; used to prove early stops really close the source.
  class ResourcefulGenerator
    include Enumerable

    def initialize(values, log)
      @values = values
      @log = log
    end

    def each
      return to_enum(:each) unless block_given?
      @log << :opened
      begin
        @values.each { |value| yield value }
        :generator_result
      ensure
        @log << :closed
      end
    end
  end

  class Boom < StandardError; end

  def setup
    @log = []
  end

  def teardown
  end

  def serve(source = nil, **opts, &factory)
    @server_enum = DRb::PullEnumerator.new(source, **opts, &factory)
    expose(@server_enum)
  end

  def remote_for(proxy, **opts)
    DRb::RemoteEnumerable.new(proxy, **opts)
  end

  def test_sequence_is_identical_across_batch_sizes
    values = (1..25).to_a
    proxy = serve(-> { values.each })
    [1, 2, 3, 7, 25, 1000].each do |batch_size|
      remote = remote_for(proxy, batch_size: batch_size)
      assert_equal(values, remote.to_a, "batch_size=#{batch_size}")
    end
  end

  def test_enumerable_api_works
    proxy = serve(-> { (1..10).each })
    remote = remote_for(proxy, batch_size: 3)
    assert_equal([2, 4, 6, 8, 10], remote.select(&:even?))
    assert_equal(55, remote.sum)
    assert_equal([1, 2, 3], remote.take(3))
  end

  def test_stop_iteration_result_is_preserved
    proxy = serve(-> { ResourcefulGenerator.new([1, 2, 3], @log) })
    remote = remote_for(proxy, batch_size: 2)
    result = remote.each { |_item| }
    assert_equal(:generator_result, result)
  end

  def test_mid_batch_error_keeps_produced_elements_and_position
    source = lambda do
      Enumerator.new do |y|
        y << 1
        y << 2
        raise Boom, 'failed at element 3'
      end
    end
    proxy = serve(source)
    remote = remote_for(proxy, batch_size: 10)
    produced = []
    error = assert_raise(Boom) do
      remote.each { |item| produced << item }
    end
    assert_equal('failed at element 3', error.message)
    assert_equal([1, 2], produced)
  end

  def test_break_releases_cursor_and_closes_resource
    proxy = serve(-> { ResourcefulGenerator.new((1..100).to_a, @log) })
    remote = remote_for(proxy, batch_size: 5)
    seen = []
    remote.each do |item|
      seen << item
      break
    end
    assert_equal([1], seen)
    assert_equal([:opened, :closed], @log)
    assert_equal(0, @server_enum.active_cursor_count)
  end

  def test_full_iteration_releases_cursor_and_closes_resource
    proxy = serve(-> { ResourcefulGenerator.new([1, 2, 3], @log) })
    remote_for(proxy, batch_size: 2).to_a
    assert_equal([:opened, :closed], @log)
    assert_equal(0, @server_enum.active_cursor_count)
  end

  def test_close_releases_in_progress_cursor
    proxy = serve(-> { ResourcefulGenerator.new((1..100).to_a, @log) })
    remote = remote_for(proxy, batch_size: 5)
    assert_raise(RuntimeError) do
      remote.each do |_item|
        remote.close
        raise 'stop iterating'
      end
    end
    assert_equal([:opened, :closed], @log)
    assert_equal(0, @server_enum.active_cursor_count)
  end

  def test_idle_cursors_are_reaped
    proxy = serve(-> { (1..10).each }, idle_timeout: 0)
    stale = proxy.open_cursor
    stale.pull(1, 1 << 20)
    assert_equal(1, @server_enum.active_cursor_count)
    proxy.open_cursor # opening a cursor sweeps idle ones
    assert_equal(1, @server_enum.active_cursor_count)
    assert(stale.closed?)
  end

  def test_nested_iterations_have_independent_positions
    proxy = serve(-> { (1..5).each })
    remote = remote_for(proxy, batch_size: 2)
    outer = remote.each
    assert_equal(1, outer.next)
    assert_equal([1, 2, 3, 4, 5], remote.to_a)
    assert_equal(2, outer.next)
    assert_equal([3, 4, 5], [outer.next, outer.next, outer.next])
  end

  def test_oversized_element_raises_clear_error
    big = 'x' * 4096
    proxy = serve(-> { ['small', big, 'never reached'].each })
    remote = remote_for(proxy, batch_size: 10, max_bytes: 1024)
    produced = []
    error = assert_raise(DRb::PullEnumerator::ElementTooLarge) do
      remote.each { |item| produced << item }
    end
    assert_match(/exceeds the batch byte limit of 1024 bytes/, error.message)
    assert_equal(['small'], produced)
  end

  def test_byte_limit_splits_batches_without_losing_elements
    values = ('a'..'j').map { |c| c * 64 }
    proxy = serve(-> { values.each })
    remote = remote_for(proxy, batch_size: 100, max_bytes: 150)
    assert_equal(values, remote.to_a)
  end

  def test_pull_on_closed_cursor_raises
    proxy = serve(-> { (1..3).each })
    cursor = proxy.open_cursor
    cursor.close
    assert_raise(DRb::PullEnumerator::ClosedCursor) do
      cursor.pull(1, 1 << 20)
    end
  end

  def test_batch_and_errors_survive_marshalling
    batch = DRb::PullEnumerator::Batch.new([1, 'two'], true, :result, nil)
    copy = Marshal.load(Marshal.dump(batch))
    assert_equal([1, 'two'], copy.items)
    assert(copy.done?)
    assert_equal(:result, copy.result)
    assert_nil(copy.error)

    error = DRb::PullEnumerator::ElementTooLarge.new(2048, 1024)
    copy = Marshal.load(Marshal.dump(error))
    assert_equal(2048, copy.size)
    assert_equal(1024, copy.max_bytes)
    assert_match(/exceeds the batch byte limit/, copy.message)
  end
end

# Exercises the proxy logic against the server object directly; always
# runs, even in sandboxes without any socket access.
class TestPullEnumeratorInProcess < Test::Unit::TestCase
  include PullEnumeratorTests

  def expose(server_enum)
    server_enum
  end
end

# Simulates DRb's pass-by-value semantics in-process: arguments and
# return values cross a Marshal round trip, while DRbUndumped objects
# (the PullEnumerator itself and its cursors) pass by reference.
class TestPullEnumeratorMarshalled < Test::Unit::TestCase
  include PullEnumeratorTests

  class MarshallingProxy
    def initialize(target)
      @target = target
    end

    def method_missing(name, *args)
      args = Marshal.load(Marshal.dump(args))
      result = @target.__send__(name, *args)
      if result.is_a?(DRb::PullEnumerator) ||
         result.is_a?(DRb::PullEnumerator::Cursor)
        MarshallingProxy.new(result)
      else
        Marshal.load(Marshal.dump(result))
      end
    end

    def respond_to_missing?(name, include_private = false)
      @target.respond_to?(name, include_private)
    end
  end

  def expose(server_enum)
    MarshallingProxy.new(server_enum)
  end
end

# Exercises the same behavior through a real DRb round trip.
class TestPullEnumeratorOverDRb < Test::Unit::TestCase
  include PullEnumeratorTests

  def setup
    super
    @socket = File.join(Dir.tmpdir, "drb-pull-#{$$}.sock")
    DRb.start_service("drbunix://#{@socket}")
  rescue Errno::EPERM, Errno::EACCES, SocketError
    omit('DRb transport is not available in this environment')
  end

  def teardown
    DRb.stop_service
    DRb::DRbConn.stop_pool
    File.unlink(@socket) if @socket && File.exist?(@socket)
  end

  def expose(server_enum)
    service = DRb::DRbServer.new("drbunix://#{@socket}", server_enum)
    DRb::DRbObject.new_with_uri(service.uri)
  rescue Errno::EPERM, Errno::EACCES, SocketError
    omit('DRb transport is not available in this environment')
  end
end
