# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/barrier'

describe 'Rack::Attack::MemoryStore' do
  before do
    @store = Rack::Attack::MemoryStore.new
  end

  it 'reads and writes values' do
    @store.write('key', 42)

    _(@store.read('key')).must_equal 42
  end

  it 'returns nil for missing keys' do
    _(@store.read('missing')).must_be_nil
  end

  it 'deletes keys' do
    @store.write('key', 42)
    @store.delete('key')

    _(@store.read('key')).must_be_nil
  end

  it 'increments uninitialized keys' do
    _(@store.increment('key', 3)).must_equal 3
    _(@store.read('key')).must_equal 3
  end

  it 'expires keys after their TTL' do
    @store.write('key', 42, expires_in: 0)

    _(@store.read('key')).must_be_nil
  end

  it 'deletes keys matching a pattern' do
    @store.write('rack::attack:1:a', 1)
    @store.write('rack::attack:1:b', 2)
    @store.write('other', 3)

    @store.delete_matched(/rack::attack/)

    _(@store.read('rack::attack:1:a')).must_be_nil
    _(@store.read('rack::attack:1:b')).must_be_nil
    _(@store.read('other')).must_equal 3
  end

  describe '#atomic_update' do
    it 'yields nil for missing keys and stores the result' do
      result = @store.atomic_update('key') { |current| current.nil? ? 10 : 0 }

      _(result).must_equal 10
      _(@store.read('key')).must_equal 10
    end

    it 'yields the current value' do
      @store.write('key', 5)

      @store.atomic_update('key') { |current| current + 1 }

      _(@store.read('key')).must_equal 6
    end

    it 'removes the key when the block returns nil' do
      @store.write('key', 5)

      @store.atomic_update('key') { |_current| nil }

      _(@store.read('key')).must_be_nil
    end

    it 'applies a TTL to the stored value' do
      @store.atomic_update('key', expires_in: 0) { |_current| 1 }

      _(@store.read('key')).must_be_nil
    end

    it 'never loses concurrent updates' do
      thread_count = 8
      updates_per_thread = 200
      barrier = Barrier.new(thread_count)

      threads = thread_count.times.map do
        Thread.new do
          barrier.wait
          updates_per_thread.times do
            @store.atomic_update('counter') { |current| (current || 0) + 1 }
          end
        end
      end
      threads.each(&:join)

      _(@store.read('counter')).must_equal thread_count * updates_per_thread
    end
  end
end
