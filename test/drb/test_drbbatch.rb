# frozen_string_literal: false
require_relative 'drbtest'
require_relative 'ut_drbbatch'

module DRbTests
  class << self
    attr_accessor :request_count
  end
  self.request_count = 0

  # Counts DRb requests sent by this process, so tests can assert how
  # many round trips a batch commit takes.
  module RequestCounter
    def send_request(stream, ref, msg_id, arg, b)
      DRbTests.request_count += 1
      super
    end
  end
end

DRb::DRbMessage.prepend(DRbTests::RequestCounter)

module DRbTests

  class TestDRbBatchValidation < Test::Unit::TestCase
    def setup
      @root = DRb::DRbObject.new_with_uri('druby://localhost:12345')
    end

    def test_forward_reference_rejected
      batch = DRb::DRbBatch.new(@root)
      self_slot = DRb::DRbBatch::Slot.new(batch.token, 0)
      assert_raise(DRb::DRbBatch::ForwardReferenceError) do
        batch.call(:get_account, self_slot)
      end

      batch.call(:get_account, 1)
      future_slot = DRb::DRbBatch::Slot.new(batch.token, 7)
      assert_raise(DRb::DRbBatch::ForwardReferenceError) do
        batch.call(:get_account, future_slot)
      end
    end

    def test_cross_batch_reference_rejected
      batch_a = DRb::DRbBatch.new(@root)
      batch_b = DRb::DRbBatch.new(@root)
      slot = batch_a.call(:get_account, 1)
      assert_raise(DRb::DRbBatch::CrossBatchReferenceError) do
        batch_b.call(:tagged, slot, 'x')
      end
      assert_raise(DRb::DRbBatch::CrossBatchReferenceError) do
        batch_b.call_on(slot, :profile)
      end
    end

    def test_cycle_rejected
      batch = DRb::DRbBatch.new(@root)
      s0 = batch.call(:get_account, 1)
      s1 = batch.call_on(s0, :profile)
      # corrupt the batch so that call 0 depends on the result of call 1
      calls = batch.instance_variable_get(:@calls)
      calls[0].receiver = s1
      assert_raise(DRb::DRbBatch::CyclicReferenceError) do
        batch.__send__(:validate!)
      end
    end

    def test_invalid_receiver_rejected
      batch = DRb::DRbBatch.new(@root)
      assert_raise(DRb::DRbBatch::SlotError) do
        batch.call_on(Object.new, :profile)
      end
    end

    def test_slots_in_nested_args_accepted
      batch = DRb::DRbBatch.new(@root)
      s0 = batch.call(:get_account, 1)
      batch.call(:tagged, [s0], 'x')
      batch.call(:tagged, { :value => s0 }, 'y')
      assert_equal(3, batch.size)
    end

    def test_blocks_rejected
      batch = DRb::DRbBatch.new(@root)
      assert_raise(DRb::DRbBatch::Error) do
        batch.call(:get_account, 1) { }
      end
    end
  end
end

module DRbTests

  # Runs the server side executor in process, without going through
  # the wire.  A socket-less DRbServer stand-in is installed as the
  # primary server so that undumpable results can be exported as
  # DRbObject references, exactly like on a real server.
  class TestDRbBatchExecutor < Test::Unit::TestCase
    def setup
      @front = BatchFront.new
      @server = DRb::DRbServer.allocate
      @server.instance_variable_set(:@front, @front)
      @server.instance_variable_set(:@idconv, DRb::DRbIdConv.new)
      @saved_primary = DRb.instance_variable_get(:@primary_server)
      DRb.instance_variable_set(:@primary_server, @server)
      @executor = DRb::DRbBatch::Executor.new(@server)
    end

    def teardown
      DRb.instance_variable_set(:@primary_server, @saved_primary)
    end

    def build_payload
      root = DRb::DRbObject.new_with_uri('druby://localhost:12345')
      batch = DRb::DRbBatch.new(root)
      yield batch
      batch.__send__(:payload)
    end

    def test_dependent_chain_and_independent_branch
      payload = build_payload do |batch|
        s0 = batch.call(:get_account, 7)
        s1 = batch.call_on(s0, :profile)
        batch.call_on(s1, :summary)
        batch.call(:heartbeat)
      end
      outcomes = @executor.execute(@front, payload)
      assert_equal([:ok, :ok, :ok, :ok], outcomes.collect(&:status))
      assert_equal('summary of account 7', outcomes[2].value)
      assert_equal(:pong, outcomes[3].value)
      # undumpable results follow the usual pass-by-reference rule
      assert_equal(DRb::DRbObject, outcomes[0].value.class)
      assert_equal(DRb::DRbObject, outcomes[1].value.class)
      assert_equal([:get_account, :profile, :summary, :heartbeat],
                   @front.call_log)
    end

    def test_failed_branch_skips_dependents_and_keeps_error
      payload = build_payload do |batch|
        s0 = batch.call(:get_account, 9)
        s1 = batch.call_on(s0, :profile)
        s2 = batch.call_on(s1, :explode)
        batch.call_on(s2, :summary)
        batch.call(:heartbeat)
      end
      outcomes = @executor.execute(@front, payload)
      assert_equal([:ok, :ok, :error, :skipped, :ok],
                   outcomes.collect(&:status))
      assert_equal('boom from account 9', outcomes[2].error.message)
      # the skipped call keeps the original error of its dependency
      assert_equal('boom from account 9', outcomes[3].error.message)
      # the independent branch still ran, the dependent call did not,
      # and the failed call was not replayed
      assert_equal([:get_account, :profile, :explode, :heartbeat],
                   @front.call_log)
    end

    def test_slot_reference_in_arguments
      payload = build_payload do |batch|
        s0 = batch.call(:get_account, 3)
        s1 = batch.call_on(s0, :profile)
        s2 = batch.call_on(s1, :summary)
        batch.call(:tagged, [s2, 'inner'], 'outer')
      end
      outcomes = @executor.execute(@front, payload)
      assert_equal([['summary of account 3', 'inner'], 'outer'],
                   outcomes[3].value)
    end

    def test_server_rejects_cross_batch_slot
      payload = build_payload { |batch| batch.call(:heartbeat) }
      foreign = DRb::DRbBatch::Slot.new('another-batch-token', 0)
      payload[1] << [nil, :tagged, [foreign, 'x']]
      outcomes = @executor.execute(@front, payload)
      assert_equal(:ok, outcomes[0].status)
      assert_equal(:error, outcomes[1].status)
      assert_equal(DRb::DRbBatch::CrossBatchReferenceError,
                   outcomes[1].error.class)
    end

    def test_server_rejects_forward_slot
      payload = build_payload { |batch| batch.call(:heartbeat) }
      future = DRb::DRbBatch::Slot.new(payload[0], 5)
      payload[1] << [nil, :tagged, [future, 'x']]
      outcomes = @executor.execute(@front, payload)
      assert_equal(:error, outcomes[1].status)
      assert_equal(DRb::DRbBatch::ForwardReferenceError,
                   outcomes[1].error.class)
    end

    def test_result_set_access
      slots = []
      payload = build_payload do |batch|
        s0 = batch.call(:get_account, 9)
        s1 = batch.call_on(s0, :profile)
        s2 = batch.call_on(s1, :explode)
        s3 = batch.call_on(s2, :summary)
        s4 = batch.call(:heartbeat)
        slots.replace([s0, s1, s2, s3, s4])
      end
      outcomes = @executor.execute(@front, payload)
      results = DRb::DRbBatch::ResultSet.new(payload[0], outcomes)

      assert_equal(:pong, results[slots[4]])
      assert_raise(RuntimeError) { results[slots[2]] }
      skipped = assert_raise(DRb::DRbBatch::SkippedError) do
        results[slots[3]]
      end
      assert_equal('boom from account 9', skipped.original_error.message)
      assert_equal(5, results.size)
      assert(results.all? { |outcome| DRb::DRbBatch::Outcome === outcome })
    end

    def test_commit_against_local_server
      uri = 'druby://localhost:54321'
      @server.instance_variable_set(:@exported_uri, [uri])
      root = DRb::DRbObject.new_with_uri(uri)
      batch = DRb::DRbBatch.new(root)
      s0 = batch.call(:get_account, 5)
      s1 = batch.call_on(s0, :profile)
      s2 = batch.call_on(s1, :summary)
      s3 = batch.call(:heartbeat)
      results = batch.commit
      assert_equal('summary of account 5', results[s2])
      assert_equal(:pong, results[s3])
      assert_equal([:get_account, :profile, :summary, :heartbeat],
                   @front.call_log)
    ensure
      @server.instance_variable_set(:@exported_uri, [])
    end

    def test_invoke_method_dispatches_batch
      payload = build_payload do |batch|
        s0 = batch.call(:get_account, 4)
        s1 = batch.call_on(s0, :profile)
        batch.call_on(s1, :summary)
      end
      front = @front
      client = Object.new
      client.define_singleton_method(:recv_request) do
        [front, '__drb_batch__', [payload], nil]
      end
      invoke = DRb::DRbServer::InvokeMethod.new(@server, client)
      succ, result = invoke.perform
      assert_equal(true, succ)
      assert_equal([:ok, :ok, :ok], result.collect(&:status))
      assert_equal('summary of account 4', result[2].value)
      assert_equal([:get_account, :profile, :summary], @front.call_log)
    end
  end

  # End to end tests against a real dRuby service.  They assert the
  # number of round trips a batch takes and the set of methods that
  # were actually invoked on the server.
  class TestDRbBatch < Test::Unit::TestCase
    include DRbBase

    def setup
      super
      setup_service 'ut_drbbatch.rb'
    end

    def test_dependent_chain_and_independent_branch
      # the naive call chain takes one round trip per call
      DRbTests.request_count = 0
      summary = @there.get_account(7).profile.summary
      assert_equal('summary of account 7', summary)
      assert_equal(3, DRbTests.request_count)

      @there.reset_log
      batch = DRb::DRbBatch.new(@there)
      s0 = batch.call(:get_account, 7)
      s1 = batch.call_on(s0, :profile)
      s2 = batch.call_on(s1, :summary)
      s3 = batch.call(:heartbeat)

      DRbTests.request_count = 0
      results = batch.commit
      assert_equal(1, DRbTests.request_count)

      assert_equal('summary of account 7', results[s2])
      assert_equal(:pong, results[s3])
      # undumpable intermediate results are passed by reference,
      # marshalable ones by value, as with ordinary dRuby calls
      assert_equal(DRb::DRbObject, results.outcome(s0).value.class)
      assert_equal(String, results.outcome(s2).value.class)
      assert_equal([:get_account, :profile, :summary, :heartbeat],
                   @there.call_log)
    end

    def test_failed_branch_skips_dependents
      @there.reset_log
      batch = DRb::DRbBatch.new(@there)
      s0 = batch.call(:get_account, 9)
      s1 = batch.call_on(s0, :profile)
      s2 = batch.call_on(s1, :explode)
      s3 = batch.call_on(s2, :summary)
      s4 = batch.call(:heartbeat)

      DRbTests.request_count = 0
      results = batch.commit
      assert_equal(1, DRbTests.request_count)

      assert(results.outcome(s0).ok?)
      assert(results.outcome(s1).ok?)
      assert(results.outcome(s2).error?)
      assert_equal('boom from account 9', results.outcome(s2).error.message)
      assert(results.outcome(s3).skipped?)
      assert_equal('boom from account 9', results.outcome(s3).error.message)
      assert(results.outcome(s4).ok?)

      assert_raise(RuntimeError) { results[s2] }
      skipped = assert_raise(DRb::DRbBatch::SkippedError) { results[s3] }
      assert_equal('boom from account 9', skipped.original_error.message)

      # the failed call ran exactly once (no rollback, no replay), the
      # dependent call was skipped, and the independent branch ran
      assert_equal([:get_account, :profile, :explode, :heartbeat],
                   @there.call_log)
    end

    def test_slot_reference_in_arguments
      batch = DRb::DRbBatch.new(@there)
      s0 = batch.call(:get_account, 3)
      s1 = batch.call_on(s0, :profile)
      s2 = batch.call_on(s1, :summary)
      s3 = batch.call(:tagged, [s2, 'inner'], 'outer')
      results = batch.commit
      assert_equal([['summary of account 3', 'inner'], 'outer'], results[s3])
    end

    def test_commit_only_once
      batch = DRb::DRbBatch.new(@there)
      batch.call(:heartbeat)
      batch.commit
      assert_raise(DRb::DRbBatch::Error) { batch.commit }
      assert_raise(DRb::DRbBatch::Error) { batch.call(:heartbeat) }
    end
  end
end
