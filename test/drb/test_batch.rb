# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb'

module DRbBatchTest
  # Minimal in-process stand-in for DRbServer, so the batch round trip
  # can be exercised without opening sockets.  DRbObject references are
  # resolved through the usual DRbIdConv object space.
  class LoopbackServer
    URI = "drbloopback://local".freeze

    def initialize
      @idconv = DRb::DRbIdConv.new
    end

    def uri
      URI
    end

    def here?(uri)
      uri == URI
    end

    def to_obj(ref)
      @idconv.to_obj(ref)
    end

    def to_id(obj)
      @idconv.to_id(obj)
    end

    def check_insecure_method(obj, msg_id)
    end

    def config
      {}
    end
  end

  # Simulates the DRb wire: the batch request and its reply are
  # marshalled and unmarshalled exactly once, like DRbMessage does.
  class LoopbackWire
    def initialize(front)
      @front = front
    end

    def execute_batch(token, ops)
      token, ops = Marshal.load(Marshal.dump([token, ops]))
      results = @front.execute_batch(token, ops)
      Marshal.load(Marshal.dump(results))
    end
  end

  class Profile
    include DRbUndumped
    def initialize(service)
      @service = service
    end

    def summary
      @service.record(:summary)
      "summary-text"
    end
  end

  class Account
    include DRbUndumped
    def initialize(service)
      @service = service
    end

    def profile
      @service.record(:profile)
      Profile.new(@service)
    end
  end

  class Service
    include DRb::Batch::Executor

    attr_reader :log, :submit_count

    def initialize
      @log = []
      @submit_count = 0
    end

    def record(name)
      @log << name
    end

    def execute_batch(token, ops)
      @submit_count += 1
      super
    end

    def get_account(id)
      record(:get_account)
      Account.new(self)
    end

    def ping
      record(:ping)
      "pong"
    end

    def echo(value)
      record(:echo)
      value
    end

    def explode
      record(:explode)
      raise "boom"
    end
  end
end

class TestDRbBatch < Test::Unit::TestCase
  def setup
    DRb.primary_server = DRbBatchTest::LoopbackServer.new
    @service = DRbBatchTest::Service.new
    @front = DRb::DRbObject.new(@service)
    @executor = DRbBatchTest::LoopbackWire.new(@service)
  end

  def teardown
    DRb.primary_server = nil
  end

  def test_dependent_chain_and_independent_branch
    batch = DRb::Batch.new(@executor)
    account = batch.call(@front, :get_account, 42)
    profile = batch.call(account, :profile)
    summary = batch.call(profile, :summary)
    pong = batch.call(@front, :ping)
    assert_equal 4, batch.size

    results = batch.submit

    # a single submit carries the whole batch
    assert_equal 1, @service.submit_count
    # each recorded call ran exactly once, in order
    assert_equal [:get_account, :profile, :summary, :ping], @service.log

    assert_equal 4, results.size
    assert(results.all?(&:ok?))
    # undumped results come back as references (locally resolved here)
    assert_kind_of DRbBatchTest::Account, results[0].value
    assert_kind_of DRbBatchTest::Profile, results[1].value
    # plain values come back by value
    assert_equal "summary-text", results[2].value
    assert_equal "pong", results[3].value
  end

  def test_failed_branch_skips_dependents_but_independent_branch_runs
    batch = DRb::Batch.new(@executor)
    bad = batch.call(@front, :explode)
    dependent = batch.call(bad, :profile)
    transitive = batch.call(dependent, :summary)
    ok = batch.call(@front, :ping)

    results = batch.submit

    # the failed call ran once, its dependents never ran, and the
    # independent branch still ran
    assert_equal [:explode, :ping], @service.log

    assert_equal :error, results[0].status
    assert_kind_of RuntimeError, results[0].error
    assert_equal "boom", results[0].error.message

    assert results[1].skipped?
    assert results[2].skipped?
    # skipped results keep the original error
    assert_kind_of RuntimeError, results[1].error
    assert_equal "boom", results[1].error.message
    assert_equal "boom", results[2].error.message

    assert results[3].ok?
    assert_equal "pong", results[3].value
  end

  def test_slot_references_inside_arguments
    batch = DRb::Batch.new(@executor)
    summary = batch.call(@front, :echo, "hello")
    batch.call(@front, :echo, [summary, { "k" => summary }])

    results = batch.submit

    assert_equal ["hello", { "k" => "hello" }], results[1].value
  end

  def test_cross_batch_reference_is_rejected
    batch1 = DRb::Batch.new(@executor)
    batch2 = DRb::Batch.new(@executor)
    slot = batch1.call(@front, :ping)

    assert_raise(DRb::Batch::BatchError) do
      batch2.call(slot, :upcase)
    end
  end

  def test_forward_reference_is_rejected
    batch = DRb::Batch.new(@executor)
    batch.call(@front, :ping)
    future = DRb::Batch::SlotRef.new(batch.token, 1)

    assert_raise(DRb::Batch::BatchError) do
      batch.call(future, :upcase)
    end
  end

  def test_cycle_is_rejected_by_server
    token = "test-cycle"
    slot = DRb::Batch::SlotRef.new(token, 1)
    ops = [
      [slot, :upcase, []],
      [@front, :ping, []],
    ]

    assert_raise(DRb::Batch::BatchError) do
      @service.execute_batch(token, ops)
    end
    assert_equal [], @service.log
  end

  def test_batch_can_be_submitted_only_once
    batch = DRb::Batch.new(@executor)
    batch.call(@front, :ping)
    batch.submit

    assert_raise(DRb::Batch::BatchError) { batch.submit }
    assert_raise(DRb::Batch::BatchError) { batch.call(@front, :ping) }
  end
end
