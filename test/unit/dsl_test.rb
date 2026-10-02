# frozen_string_literal: true

require 'rubygems'
require 'minitest/autorun'
require 'rack/cors'

describe Rack::Cors, 'DSL' do
  it 'should support explicit config object dsl mode' do
    cors = Rack::Cors.new(proc {}) do |cfg|
      cfg.allow do |allow|
        allow.origins 'localhost:3000', '127.0.0.1:3000' do |source, env|
          source == 'http://10.10.10.10:3000' &&
            env['USER_AGENT'] == 'test-agent'
        end
        allow.resource '/get-only', methods: :get
        allow.resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    _(resources.length).must_equal 1
    _(resources.first.allow_origin?('http://localhost:3000')).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'test-agent' })).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3001', { 'USER_AGENT' => 'test-agent' })).wont_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'other-agent' })).wont_equal true
  end

  it 'should support implicit config object dsl mode' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'localhost:3000', '127.0.0.1:3000' do |source, env|
          source == 'http://10.10.10.10:3000' &&
            env['USER_AGENT'] == 'test-agent'
        end
        resource '/get-only', methods: :get
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    _(resources.length).must_equal 1
    _(resources.first.allow_origin?('http://localhost:3000')).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'test-agent' })).must_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3001', { 'USER_AGENT' => 'test-agent' })).wont_equal true
    _(resources.first.allow_origin?('http://10.10.10.10:3000', { 'USER_AGENT' => 'other-agent' })).wont_equal true
  end

  it 'should support "file://" origin' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'file://'
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources

    _(resources.first.allow_origin?('file://')).must_equal true
  end

  it 'should default credentials option to false' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'example.net'
        resource '/', headers: :any
      end
    end
    resources = cors.send :all_resources
    _(resources.first.resources.first.credentials).must_equal false
  end

  it 'should distinguish :any, defaults and unconfigured values' do
    cors = Rack::Cors.new(proc {}) do
      allow do
        origins 'example.net'
        resource '/configured', methods: :any, headers: :any, max_age: 100, expose: 'x'
        resource '/omitted'
      end
    end
    configured, omitted = cors.send(:all_resources).first.resources

    _(configured.methods_configured).must_equal true
    _(configured.headers_configured).must_equal true
    _(configured.max_age_configured).must_equal true
    _(configured.expose_configured).must_equal true
    _(configured.headers).must_equal :any

    _(omitted.methods_configured).must_equal false
    _(omitted.headers_configured).must_equal false
    _(omitted.max_age_configured).must_equal false
    _(omitted.expose_configured).must_equal false
    _(omitted.methods).must_equal ['get']
    _(omitted.headers).must_be_nil
    _(omitted.max_age).must_equal 7200
    _(omitted.expose).must_be_nil
  end
end
