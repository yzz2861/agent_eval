# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb'
require 'drb/unix'
require 'drb/pull_enumerator'

class TestDRbPullEnumerator < Test::Unit::TestCase
  class ReportService
    def initialize
      @mutex = Mutex.new
      @closed = []
    end

    def records(count=20, batch_size: 5, byte_limit: 1 << 20)
      DRb::PullEnumerator::Server.new((1..count).to_a,
                                      batch_size: batch_size,
                                      byte_limit: byte_limit)
    end

    def completed_result
      DRb::PullEnumerator::Server.new(batch_size: 3) do |yielder|
        1.upto(7) { |i| yielder << i }
        :report_done
      end
    end

    def failing_at(index)
      DRb::PullEnumerator::Server.new(batch_size: 4) do |yielder|
        1.upto(20) do |i|
          raise "failure at #{i}" if i == index
          yielder << i
        end
      end
    end

    def oversized
      DRb::PullEnumerator::Server.new(['ok', 'x' * 100],
                                      batch_size: 2,
                                      byte_limit: 30)
    end

    def byte_split
      DRb::PullEnumerator::Server.new(['a' * 12, 'b' * 12, 'c'],
                                      batch_size: 10,
                                      byte_limit: 22)
    end

    def tracked(name, batch_size: 2)
      DRb::PullEnumerator::Server.new(batch_size: batch_size) do |yielder|
        begin
          1.upto(10) { |i| yielder << [name, i] }
        ensure
          @mutex.synchronize { @closed << name }
        end
      end
    end

    def closed?(name)
      @mutex.synchronize { @closed.include?(name) }
    end
  end

  def setup
    @service = ReportService.new
    @server = nil
    @socket_path = 'd.sock'
    @target = begin
      socket = File.expand_path(@socket_path)
      File.unlink(@socket_path) if File.exist?(@socket_path)
      @server = DRb::DRbServer.new("drbunix:#{socket}", @service)
      @remote = true
      DRb::DRbObject.new_with_uri(@server.uri)
    rescue SystemCallError
      @remote = false
      @service
    end
  end

  def teardown
    @server&.stop_service
    DRb::DRbConn.stop_pool
    File.unlink(@socket_path) if File.exist?(@socket_path)
  end

  def test_different_batch_sizes_return_the_same_sequence
    [1, 2, 3, 5, 7, 100].each do |batch_size|
      pull = @target.records(20, batch_size: batch_size)
      assert_equal((1..20).to_a, pull.to_a, "batch size #{batch_size}")
    end
  end

  def test_enumerable_usage_and_nested_iteration_have_independent_positions
    pull = @target.records(8, batch_size: 3)
    assert_equal((1..8).to_a, pull.to_a)
    assert_equal([2, 4, 6, 8], pull.select(&:even?).first(4))

    outer = []
    nested = []
    pull.each do |outer_value|
      outer << outer_value
      pull.each { |inner_value| nested << inner_value }
      break if outer_value == 2
    end

    assert_equal([1, 2], outer)
    assert_equal([1, 2, 3, 4, 5, 6, 7, 8] * 2, nested)
  end

  def test_stop_iteration_result_is_preserved
    pull = @target.completed_result
    assert_equal(:report_done, pull.each { })
  end

  def test_stateful_enumerator_requires_repeatable_factory
    error = assert_raise(ArgumentError) do
      DRb::PullEnumerator::Server.new((1..3).each)
    end
    assert_match(/re-enumerable|new enumerator/, error.message)

    count = 0
    pull = DRb::PullEnumerator::Server.new do |yielder|
      count += 1
      1.upto(3) { |i| yielder << i }
    end
    assert_equal([1, 2, 3], pull.to_a)
    assert_equal([1, 2, 3], pull.to_a)
    assert_equal(2, count)
  end

  def test_partial_batch_elements_are_returned_with_failure_position
    pull = @target.failing_at(6)
    values = []
    error = assert_raise(RuntimeError) do
      pull.each { |value| values << value }
    end
    assert_equal((1..5).to_a, values)
    assert_equal('failure at 6', error.message)
    assert_equal(5, error.instance_variable_get(:@pull_index))
  end

  def test_oversized_single_element_has_clear_error_and_index
    pull = @target.oversized
    values = []
    error = assert_raise(DRb::PullEnumerator::ElementTooLargeError) do
      pull.each { |value| values << value }
    end
    assert_equal(['ok'], values)
    assert_match(/exceeds byte limit/, error.message)
    assert_equal(1, error.instance_variable_get(:@pull_index))
  end

  def test_byte_limit_splits_elements_without_repeating_or_losing
    pull = @target.byte_split
    assert_equal(['a' * 12, 'b' * 12, 'c'], pull.to_a)
  end

  def test_break_closes_server_generator
    pull = @target.tracked('break')
    pull.each { break }
    sleep 0.05
    assert(@service.closed?('break'))
  end

  def test_connection_handles_close_cursors_from_multiple_enumerators
    drb = Thread.current['DRb'] ||= {}
    original_client = drb['client']
    drb['client'] = Object.new
    first = @service.tracked('first', batch_size: 1)
    second = @service.tracked('second', batch_size: 1)
    first_id = first.open_cursor
    second_id = second.open_cursor
    first.pull_cursor(first_id)
    second.pull_cursor(second_id)

    handles = drb['pull_enumerator_servers']
    handles.uniq.each { |server, id| server.close_cursor(id) }

    assert(@service.closed?('first'))
    assert(@service.closed?('second'))
  ensure
    drb['client'] = original_client
    drb&.delete('pull_enumerator_servers')
  end

  def test_low_level_close_releases_cursor
    omit('low-level remote cursor cleanup is covered by disconnect test') unless @remote

    pull = @target.tracked('close', batch_size: 2)
    cursor = pull.open_cursor
    assert_equal([['close', 1], ['close', 2]],
                 pull.pull_cursor(cursor).elements)
    pull.close_cursor(cursor)
    sleep 0.05
    assert(@service.closed?('close'))
  end

  def test_connection_disconnect_closes_open_cursor
    omit('UNIX socket support is unavailable in this sandbox') unless @remote

    pull = @target.tracked('disconnect', batch_size: 2)
    cursor = pull.open_cursor
    assert_equal([['disconnect', 1], ['disconnect', 2]],
                 pull.pull_cursor(cursor).elements)
    DRb::DRbConn.stop_pool
    sleep 0.1
    assert(@service.closed?('disconnect'))
  end
end
