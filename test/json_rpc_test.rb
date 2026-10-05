# frozen_string_literal: true

require_relative 'test_helper'
require 'sinatra/json_rpc'

class JSONRPCTest < Minitest::Test
  class BusinessError < StandardError; end
  class MappedBusinessError < BusinessError; end

  def build_app(&block)
    Class.new(Sinatra::Base, &block).tap do |app|
      app.set :environment, :test
      app.set :show_exceptions, false
      app.set :raise_errors, false
    end
  end

  def rpc_app
    build_app do
      register Sinatra::JSONRPC

      json_rpc '/rpc' do
        register('sum') { |a, b| a + b }
        register('greet') { |name:| "Hello, #{name}!" }
        register('notify_only') { :done }
        register('boom') { raise JSONRPCTest::BusinessError, 'business failed' }
        register('mapped_boom') { raise JSONRPCTest::MappedBusinessError, 'mapped failure' }
        register('custom_error') { raise Sinatra::JSONRPC::Error.new(-32_042, 'custom', 'extra') }
        register('explode') { raise 'unexpected' }

        map_error JSONRPCTest::MappedBusinessError, code: -32_001, message: 'Mapped business error'
      end

      json_rpc '/rpc_settings' do
        register('boom') { raise JSONRPCTest::BusinessError, 'settings mapped' }
      end
      set :json_rpc_error_map, JSONRPCTest::BusinessError => [-32_100, 'From settings']

      registry = Sinatra::JSONRPC::Registry.new
      registry.register('double') { |n| n * 2 }
      post('/manual') { json_rpc_dispatch registry }
    end
  end

  def app
    @app ||= rpc_app
  end

  def rpc_call(payload, path = '/rpc')
    post path, payload.is_a?(String) ? payload : JSON.generate(payload),
         { 'CONTENT_TYPE' => 'application/json' }
    last_response
  end

  def rpc_json(payload, path = '/rpc')
    response = rpc_call(payload, path)
    assert_equal 200, response.status
    assert_match %r{application/json}, response.content_type
    JSON.parse(response.body)
  end

  it 'dispatches positional params and preserves numeric ids' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1, 2], 'id' => 7)
    assert_equal({ 'jsonrpc' => '2.0', 'result' => 3, 'id' => 7 }, body)
  end

  it 'dispatches named params as keyword arguments' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'greet', 'params' => { 'name' => 'ruby' }, 'id' => 1)
    assert_equal 'Hello, ruby!', body['result']
  end

  it 'preserves string ids' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1, 2], 'id' => 'req-1')
    assert_equal 'req-1', body['id']
  end

  it 'responds with null id when id is explicitly null' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1, 2], 'id' => nil)
    assert_equal 3, body['result']
    assert body.key?('id')
    assert_nil body['id']
  end

  it 'treats requests without id as notifications and returns 204' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'notify_only')
    assert_equal 204, response.status
    assert_empty response.body
  end

  it 'does not respond to notifications even when the handler raises' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'boom')
    assert_equal 204, response.status
    assert_empty response.body
  end

  it 'does not respond to notifications with unknown methods' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'nope')
    assert_equal 204, response.status
  end

  it 'returns method not found for unregistered methods' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'nope', 'id' => 1)
    assert_equal(-32_601, body['error']['code'])
    assert_equal 1, body['id']
  end

  it 'never dispatches arbitrary ruby methods' do
    %w[send object_id to_s eval system __send__].each do |name|
      body = rpc_json('jsonrpc' => '2.0', 'method' => name, 'params' => [], 'id' => 1)
      assert_equal(-32_601, body['error']['code'], "expected #{name} to be rejected")
    end
  end

  it 'returns invalid params for arity mismatches' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1], 'id' => 1)
    assert_equal(-32_602, body['error']['code'])
  end

  it 'returns invalid params when params is neither array nor object' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'sum', 'params' => 'nope', 'id' => 1)
    assert_equal(-32_602, body['error']['code'])
  end

  it 'maps business exceptions via registry map_error' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'mapped_boom', 'id' => 1)
    assert_equal(-32_001, body['error']['code'])
    assert_equal 'Mapped business error', body['error']['message']
  end

  it 'maps business exceptions via the json_rpc_error_map setting' do
    body = rpc_json({ 'jsonrpc' => '2.0', 'method' => 'boom', 'id' => 1 }, '/rpc_settings')
    assert_equal(-32_100, body['error']['code'])
    assert_equal 'From settings', body['error']['message']
  end

  it 'passes through JSONRPC::Error raised by handlers' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'custom_error', 'id' => 1)
    assert_equal(-32_042, body['error']['code'])
    assert_equal 'custom', body['error']['message']
    assert_equal 'extra', body['error']['data']
  end

  it 'returns internal error for unmapped exceptions' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'explode', 'id' => 1)
    assert_equal(-32_603, body['error']['code'])
    assert_equal 'Internal error', body['error']['message']
  end

  it 'returns parse error for malformed JSON' do
    body = rpc_json('{not json')
    assert_equal(-32_700, body['error']['code'])
    assert_nil body['id']
  end

  it 'returns invalid request for non-request payloads' do
    body = rpc_json('42')
    assert_equal(-32_600, body['error']['code'])
  end

  it 'returns invalid request for wrong jsonrpc version' do
    body = rpc_json('jsonrpc' => '1.0', 'method' => 'sum', 'params' => [1, 2], 'id' => 1)
    assert_equal(-32_600, body['error']['code'])
  end

  it 'returns invalid request for invalid id types' do
    body = rpc_json('jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1, 2], 'id' => [1])
    assert_equal(-32_600, body['error']['code'])
    assert_nil body['id']
  end

  it 'returns invalid request for empty batches' do
    body = rpc_json('[]')
    assert_equal(-32_600, body['error']['code'])
  end

  it 'processes batch members independently' do
    body = rpc_json([
      { 'jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1, 2], 'id' => 1 },
      { 'jsonrpc' => '2.0', 'method' => 'nope', 'id' => 'two' },
      { 'jsonrpc' => '2.0', 'method' => 'sum', 'params' => [1], 'id' => 3 },
      { 'not' => 'a request' },
      { 'jsonrpc' => '2.0', 'method' => 'notify_only' },
      { 'jsonrpc' => '2.0', 'method' => 'boom' },
      { 'jsonrpc' => '2.0', 'method' => 'sum', 'params' => [4, 5], 'id' => nil }
    ])
    assert_equal 5, body.length

    assert_equal({ 'jsonrpc' => '2.0', 'result' => 3, 'id' => 1 }, body[0])

    assert_equal(-32_601, body[1]['error']['code'])
    assert_equal 'two', body[1]['id']

    assert_equal(-32_602, body[2]['error']['code'])
    assert_equal 3, body[2]['id']

    assert_equal(-32_600, body[3]['error']['code'])
    assert_nil body[3]['id']

    assert_equal 9, body[4]['result']
    assert body[4].key?('id')
    assert_nil body[4]['id']
  end

  it 'returns 204 for batches containing only notifications' do
    response = rpc_call([
      { 'jsonrpc' => '2.0', 'method' => 'notify_only' },
      { 'jsonrpc' => '2.0', 'method' => 'boom' }
    ])
    assert_equal 204, response.status
    assert_empty response.body
  end

  it 'dispatches against a registry from a manual route' do
    body = rpc_json({ 'jsonrpc' => '2.0', 'method' => 'double', 'params' => [21], 'id' => 1 }, '/manual')
    assert_equal 42, body['result']
  end
end
