# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Dataloader::Source do
  class FailsToLoadSource < GraphQL::Dataloader::Source
    def fetch(keys)
      dataloader.with(FailsToLoadSource).load_all(keys)
    end
  end

  if testing_rails?
    describe "with field configuration shorthands" do
      include VulfpeckSchemaHelpers
      it "calls the configured source" do
        exec_next_only("Only exec-next uses these configs")
        result = exec_query("{ bandsCount albumsCount }")
        assert_equal 4, result["data"]["bandsCount"]
        assert_equal 6, result["data"]["albumsCount"]
      end
    end
  end

  it "raises an error when it tries too many times to sync" do
    dl = GraphQL::Dataloader.new
    dl.append_job { dl.with(FailsToLoadSource).load(1) }
    err = assert_raises RuntimeError do
      dl.run
    end
    expected_message = "FailsToLoadSource#sync tried 1000 times to load pending keys ([1]), but they still weren't loaded. There is likely a circular dependency."
    assert_equal expected_message, err.message

    dl = GraphQL::Dataloader.new(fiber_limit: 10000)
    dl.append_job { dl.with(FailsToLoadSource).load(1) }
    err = assert_raises RuntimeError do
      dl.run
    end
    expected_message = "FailsToLoadSource#sync tried 1000 times to load pending keys ([1]), but they still weren't loaded. There is likely a circular dependency or `fiber_limit: 10000` is set too low."
    assert_equal expected_message, err.message
  end

  it "is pending when waiting for false and nil" do
    dl = GraphQL::Dataloader.new
    dl.with(FailsToLoadSource).request(nil)

    source_cache = dl.instance_variable_get(:@source_cache)
    source_cache_for_source = source_cache[FailsToLoadSource]

    # The value of this changed in Ruby 3.3.3, see https://bugs.ruby-lang.org/issues/20180
    # In previous versions, it was `[{}]`, but now it's `[]`
    empty_execution_next_key = [*[]]
    source_inst = source_cache_for_source[empty_execution_next_key]
    assert_instance_of FailsToLoadSource, source_inst, "The cache includes a pending source (#{source_cache_for_source.inspect})"
    assert source_inst.pending?
  end

  class CustomKeySource < GraphQL::Dataloader::Source
    def result_key_for(record)
      record[:id]
    end

    def fetch(records)
      records.map { |r| r[:value] * 10 }
    end
  end

  it "uses a custom key when configured" do
    values = nil

    GraphQL::Dataloader.with_dataloading do |dl|
      first_req = dl.with(CustomKeySource).request({ id: 1, value: 10 })
      second_rec = dl.with(CustomKeySource).request({ id: 2, value: 20 })
      third_rec = dl.with(CustomKeySource).request({id: 1, value: 30 })

      values = [
        first_req.load,
        second_rec.load,
        third_rec.load
      ]
    end

    # There wasn't a `300` because the third requested value was de-duped to the first one.
    assert_equal [100, 200, 100], values
  end

  class NoDataloaderSchema < GraphQL::Schema
    class ThingSource < GraphQL::Dataloader::Source
      def fetch(ids)
        ids.map { |id| { name: "Thing-#{id}" } }
      end
    end

    class Thing < GraphQL::Schema::Object
      field :name, String
    end

    class Query < GraphQL::Schema::Object
      field :thing, Thing, resolve_batch: true do
        argument :id, ID
      end

      def self.thing(objects, context, id:)
        context.dataload_all(ThingSource, Array.new(objects.size, id))
      end

      def thing(id:)
        context.dataload(ThingSource, id)
      end
    end
    query(Query)
  end

  it "raises an error when used without a dataloader" do
    err = assert_raises GraphQL::Error do
      NoDataloaderSchema.execute("{ thing(id: 1) { name } }")
    end

    expected_message = exec_next_error_message "Query.thing", "GraphQL::Dataloader is not running -- add `use GraphQL::Dataloader` to your schema to use Dataloader sources."
    assert_equal expected_message, err.message
  end

  class BatchLimitedSource < GraphQL::Dataloader::Source
    max_batch_size 2

    attr_reader :batches

    def setup(dataloader)
      super
      @batches = []
    end

    def fetch(keys)
      @batches << keys.dup
      keys.map { |k| k * 10 }
    end
  end

  it "splits pending keys into slices of max_batch_size, keeping deduplication and result positions" do
    assert_nil GraphQL::Dataloader::Source.max_batch_size
    assert_equal 2, BatchLimitedSource.max_batch_size

    dl = GraphQL::Dataloader.new
    source = dl.with(BatchLimitedSource)
    assert_equal 2, source.max_batch_size
    values = nil
    dl.append_job do
      values = source.load_all([1, 2, 2, 3, 4, 5, 3])
    end
    dl.run

    assert_equal [10, 20, 20, 30, 40, 50, 30], values
    assert_equal [[1, 2], [3, 4], [5]], source.batches
  end

  class RecursiveBatchLimitedSource < GraphQL::Dataloader::Source
    max_batch_size 2

    attr_reader :batches

    def setup(dataloader)
      super
      @batches = []
    end

    def fetch(keys)
      @batches << keys.dup
      if keys.include?(:recurse)
        dataloader.with(RecursiveBatchLimitedSource).load(:extra)
      end
      keys.map(&:to_s)
    end
  end

  it "handles keys requested during fetch in a later round, not in the already-committed slice" do
    dl = GraphQL::Dataloader.new
    source = dl.with(RecursiveBatchLimitedSource)
    values = nil
    dl.append_job do
      values = source.load_all([:a, :recurse])
    end
    dl.run

    assert_equal ["a", "recurse"], values
    # `:extra` was requested while the first slice was fetching,
    # so it was fetched in its own slice afterwards.
    assert_equal [[:a, :recurse], [:extra]], source.batches
  end

  class FlakyBatchLimitedSource < GraphQL::Dataloader::Source
    max_batch_size 2

    def fetch(keys)
      if keys.include?(:boom)
        raise "boom!"
      end
      keys.map(&:to_s)
    end
  end

  it "releases other waiters when a middle slice raises an error" do
    dl = GraphQL::Dataloader.new
    outcomes = {}
    dl.append_job do
      outcomes[:a] = dl.with(FlakyBatchLimitedSource).load(:a)
    end
    dl.append_job do
      outcomes[:b] = dl.with(FlakyBatchLimitedSource).load(:b)
    end
    dl.append_job do
      err = assert_raises(RuntimeError) { dl.with(FlakyBatchLimitedSource).load(:boom) }
      outcomes[:boom] = err.message
    end
    dl.append_job do
      err = assert_raises(RuntimeError) { dl.with(FlakyBatchLimitedSource).load(:c) }
      outcomes[:c] = err.message
    end
    dl.append_job do
      outcomes[:d] = dl.with(FlakyBatchLimitedSource).load(:d)
    end
    dl.run

    # The slices were [:a, :b], [:boom, :c] and [:d]: the middle slice
    # stored the error for its own keys and the other slices still ran.
    assert_equal "a", outcomes[:a]
    assert_equal "b", outcomes[:b]
    assert_equal "boom!", outcomes[:boom]
    assert_equal "boom!", outcomes[:c]
    assert_equal "d", outcomes[:d]
  end
end
