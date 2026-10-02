# frozen_string_literal: true

require 'active_support/cache'
require_relative '../spec_helper'

OfflineExamples = Minitest::SharedExamples.new do
  it 'should write' do
    _(-> { @cache.write('cache-test-key', 'foobar', 1) }).must_raise Rack::Attack::StoreError
  end

  it 'should read' do
    _(-> { @cache.read('cache-test-key') }).must_raise Rack::Attack::StoreError
  end

  it 'should count' do
    _(-> { @cache.count('cache-test-key', 1) }).must_raise Rack::Attack::StoreError
  end

  it 'should delete' do
    _(-> { @cache.delete('cache-test-key') }).must_raise Rack::Attack::StoreError
  end
end

if defined?(Redis) && defined?(ActiveSupport::Cache::RedisCacheStore) && Redis::VERSION >= '4'
  describe 'when Redis is offline' do
    include OfflineExamples

    before do
      @cache = Rack::Attack::Cache.new
      # Use presumably unused port for Redis client
      @cache.store = ActiveSupport::Cache::RedisCacheStore.new(host: '127.0.0.1', port: 3333)
    end
  end
end

if defined?(::Dalli)
  describe 'when Memcached is offline' do
    include OfflineExamples

    before do
      Dalli.logger.level = Logger::FATAL

      @cache = Rack::Attack::Cache.new
      @cache.store = Dalli::Client.new('127.0.0.1:22122')
    end

    after do
      Dalli.logger.level = Logger::INFO
    end
  end
end

if defined?(::Dalli) && defined?(::ActiveSupport::Cache::MemCacheStore)
  describe 'when Memcached is offline' do
    include OfflineExamples

    before do
      Dalli.logger.level = Logger::FATAL

      @cache = Rack::Attack::Cache.new
      @cache.store = ActiveSupport::Cache::MemCacheStore.new('127.0.0.1:22122')
    end

    after do
      Dalli.logger.level = Logger::INFO
    end
  end
end

if defined?(Redis)
  describe 'when Redis is offline' do
    include OfflineExamples

    before do
      @cache = Rack::Attack::Cache.new
      # Use presumably unused port for Redis client
      @cache.store = Redis.new(host: '127.0.0.1', port: 3333)
    end
  end
end
