# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/freeze_time_helper'

describe Rack::Attack::Cache do
  before do
    @cache = Rack::Attack::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
  end

  describe '#count' do
    it 'returns the count together with the epoch time of its own window' do
      count, epoch_time = nil
      within_same_period do
        epoch_time = Time.now.to_i
        count, returned_epoch = @cache.count('key', 60)
        _(count).must_equal 1
        _(returned_epoch).must_equal epoch_time
      end
    end

    it 'increments inside the window key derived from the returned epoch' do
      within_same_period do
        epoch_time = Time.now.to_i
        _count, returned_epoch = @cache.count('key', 60)
        @cache.count('key', 60)

        key = "#{@cache.prefix}:#{returned_epoch / 60}:key"
        _(@cache.store.read(key)).must_equal 2
        _(returned_epoch).must_equal epoch_time
      end
    end

    it 'starts a fresh counter in a new window' do
      first_count = first_epoch = nil
      within_same_period do
        first_epoch = Time.now.to_i
        first_count, = @cache.count('key', 60)
      end
      _(first_count).must_equal 1

      Timecop.travel(Time.at(first_epoch) + 60) do
        second_count, second_epoch = @cache.count('key', 60)
        _(second_count).must_equal 1
        _(second_epoch / 60).must_equal((first_epoch / 60) + 1)
      end
    end

    it 'raises when no store is configured' do
      cache = Rack::Attack::Cache.new
      cache.instance_variable_set(:@store, nil)
      _(-> { cache.count('key', 60) }).must_raise Rack::Attack::MissingStoreError
    end
  end

  describe '#reset_count' do
    it 'deletes only the counter in the current window and leaves other windows' do
      within_same_period do
        epoch_time = Time.now.to_i
        current_key = "#{@cache.prefix}:#{epoch_time / 60}:key"
        previous_key = "#{@cache.prefix}:#{(epoch_time / 60) - 1}:key"
        @cache.store.write(current_key, 3, expires_in: 60)
        @cache.store.write(previous_key, 5, expires_in: 60)

        @cache.reset_count('key', 60)

        _(@cache.store.read(current_key)).must_be_nil
        _(@cache.store.read(previous_key)).must_equal 5
      end
    end
  end
end
