# frozen_string_literal: true

require_relative 'spec_helper'

describe Rack::Attack::Store::Memory do
  before do
    @now = 100.0
    @store = Rack::Attack::Store::Memory.new(clock: -> { @now })
  end

  it 'supports the classic counter interface' do
    _(@store.read('c')).must_be_nil
    _(@store.increment('c', 1, expires_in: 10)).must_equal 1
    _(@store.increment('c', 2, expires_in: 10)).must_equal 3
    _(@store.read('c')).must_equal 3
  end

  it 'expires values after expires_in' do
    @store.write('k', 'v', expires_in: 5)
    _(@store.read('k')).must_equal 'v'

    @now = 104.9
    _(@store.read('k')).must_equal 'v'

    @now = 105.0
    _(@store.read('k')).must_be_nil
  end

  it 'keeps the initial expiry when incrementing an existing key' do
    @store.increment('c', 1, expires_in: 5)
    @now = 104.0
    @store.increment('c', 1, expires_in: 60)
    @now = 105.0
    _(@store.read('c')).must_be_nil
  end

  describe '#delete_matched' do
    before do
      @store.write('rack::attack:1:a', 1)
      @store.write('rack::attack:1:b', 2)
      @store.write('other', 3)
    end

    it 'deletes only keys matching the regexp' do
      @store.delete_matched(/rack::attack/)
      _(@store.read('rack::attack:1:a')).must_be_nil
      _(@store.read('rack::attack:1:b')).must_be_nil
      _(@store.read('other')).must_equal 3
    end
  end

  describe '#update' do
    it 'requires a block' do
      _(-> { @store.update('k') }).must_raise ArgumentError
    end

    it 'passes nil for missing keys and stores the pair value' do
      result = @store.update('k', expires_in: 10) do |current|
        _(current).must_be_nil
        [(5.0).to_s, :created]
      end

      _(result).must_equal :created
      _(@store.read('k')).must_equal '5.0'
    end

    it 'deletes the key when the new value is nil' do
      @store.write('k', '1')
      @store.update('k') { |_| [nil, :removed] }
      _(@store.read('k')).must_be_nil
    end

    it 'serializes updates so blocks never interleave' do
      threads = 16
      iterations = 500
      @store.write('balance', '0')

      workers = Array.new(threads) do
        Thread.new do
          iterations.times do
            @store.update('balance') do |current|
              value = current.to_i
              # A context switch here must not make two reads observe the
              # same value: the whole block runs under the store lock.
              Thread.pass
              [value.succ.to_s, value.succ]
            end
          end
        end
      end
      workers.each(&:join)

      _(@store.read('balance')).must_equal (threads * iterations).to_s
    end
  end
end
