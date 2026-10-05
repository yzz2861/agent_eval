# frozen_string_literal: true

require_relative 'test_helper'
require 'sinatra/json_rpc'
require 'json'

class JsonRpcTest < Minitest::Test
  class BusinessError < StandardError; end

  def build_app(error_map: {})
    map = error_map
    Class.new(Sinatra::Base) do
      register Sinatra::JsonRpc
      set :environment, :test
      set :json_rpc_error_map, map

      rpc_method 'add' do |a, b|
        a + b
      end

      rpc_method 'greet' do |name:|
        "hello #{name}"
      end

      rpc_method 'ping' do
        'pong'
      end

      rpc_method 'fail' do
        raise JsonRpcTest::BusinessError, 'boom'
      end

      rpc_method 'explode' do
        raise 'unexpected'
      end

      post '/rpc' do
        json_rpc_call
      end
    end
  end

  attr_writer :app

  def app
    @app ||= build_app
  end

  def rpc_call(payload)
    body = payload.is_a?(String) ? payload : JSON.generate(payload)
    post '/rpc', body, 'CONTENT_TYPE' => 'application/json'
    JSON.parse(last_response.body) unless last_response.body.empty?
  end

  it 'calls a method with positional params and preserves a numeric id' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'add', 'params' => [2, 3], 'id' => 7)
    assert_equal({ 'jsonrpc' => '2.0', 'result' => 5, 'id' => 7 }, response)
    assert_equal 200, last_response.status
    assert_includes last_response.content_type, 'application/json'
  end

  it 'calls a method with named params and preserves a string id' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'greet', 'params' => { 'name' => 'ruby' }, 'id' => 'req-1')
    assert_equal({ 'jsonrpc' => '2.0', 'result' => 'hello ruby', 'id' => 'req-1' }, response)
  end

  it 'calls a method without params' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'ping', 'id' => 1)
    assert_equal 'pong', response['result']
  end

  it 'distinguishes a missing id from a null id' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'ping', 'id' => nil)
    assert_equal({ 'jsonrpc' => '2.0', 'result' => 'pong', 'id' => nil }, response)
    assert_equal 200, last_response.status
  end

  it 'does not respond to a notification' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'ping')
    assert_nil response
    assert_equal 204, last_response.status
    assert_empty last_response.body
  end

  it 'does not respond to a notification even when the handler raises' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'explode')
    assert_nil response
    assert_equal 204, last_response.status
  end

  it 'returns method not found for unknown methods' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'nope', 'id' => 1)
    assert_equal(-32_601, response['error']['code'])
    assert_equal 1, response['id']
  end

  it 'never invokes arbitrary ruby methods from the client method name' do
    %w[object_id send eval exit].each do |name|
      response = rpc_call('jsonrpc' => '2.0', 'method' => name, 'id' => 1)
      assert_equal(-32_601, response['error']['code'], "expected #{name} to be rejected")
    end
  end

  it 'returns invalid params when the handler arity does not match' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'add', 'params' => [1], 'id' => 2)
    assert_equal(-32_602, response['error']['code'])
    assert_equal 2, response['id']
  end

  it 'returns invalid params for unexpected named params' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'greet', 'params' => { 'wrong' => 1 }, 'id' => 3)
    assert_equal(-32_602, response['error']['code'])
  end

  it 'maps business exceptions to internal error by default without leaking the message' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'fail', 'id' => 4)
    assert_equal(-32_603, response['error']['code'])
    assert_equal 'Internal error', response['error']['message']
  end

  it 'maps business exceptions through the configured error map' do
    @app = build_app(error_map: { JsonRpcTest::BusinessError => { code: -32_001, message: 'business failed' } })
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'fail', 'id' => 5)
    assert_equal(-32_001, response['error']['code'])
    assert_equal 'business failed', response['error']['message']
  end

  it 'supports callable and integer error map entries' do
    @app = build_app(error_map: {
                       JsonRpcTest::BusinessError => ->(e) { { code: -32_002, message: e.message, data: 'extra' } },
                       :internal_error => -32_000
                     })
    response = rpc_call('jsonrpc' => '2.0', 'method' => 'fail', 'id' => 6)
    assert_equal(-32_002, response['error']['code'])
    assert_equal 'boom', response['error']['message']
    assert_equal 'extra', response['error']['data']

    response = rpc_call('jsonrpc' => '2.0', 'method' => 'explode', 'id' => 7)
    assert_equal(-32_000, response['error']['code'])
  end

  it 'returns a parse error for invalid JSON' do
    response = rpc_call('{not json')
    assert_equal(-32_700, response['error']['code'])
    assert_nil response['id']
  end

  it 'returns invalid request for malformed request objects' do
    response = rpc_call('jsonrpc' => '2.0', 'method' => 1, 'id' => 1)
    assert_equal(-32_600, response['error']['code'])

    response = rpc_call('jsonrpc' => '1.0', 'method' => 'ping', 'id' => 1)
    assert_equal(-32_600, response['error']['code'])

    response = rpc_call(42)
    assert_equal(-32_600, response['error']['code'])
    assert_nil response['id']
  end

  it 'returns invalid request for an empty batch' do
    response = rpc_call([])
    assert_equal(-32_600, response['error']['code'])
    assert_nil response['id']
  end

  it 'handles batches, isolating broken entries and skipping notifications' do
    response = rpc_call([
                          { 'jsonrpc' => '2.0', 'method' => 'add', 'params' => [1, 2], 'id' => 1 },
                          { 'jsonrpc' => '2.0', 'method' => 'ping' },
                          { 'jsonrpc' => '2.0', 'method' => 'nope', 'id' => 'two' },
                          { 'jsonrpc' => '2.0', 'method' => 'greet', 'params' => { 'name' => 'x' }, 'id' => 3 },
                          { 'broken' => true },
                          7
                        ])
    assert_equal 5, response.length
    assert_equal({ 'jsonrpc' => '2.0', 'result' => 3, 'id' => 1 }, response[0])
    assert_equal(-32_601, response[1]['error']['code'])
    assert_equal 'two', response[1]['id']
    assert_equal 'hello x', response[2]['result']
    assert_equal(-32_600, response[3]['error']['code'])
    assert_nil response[3]['id']
    assert_equal(-32_600, response[4]['error']['code'])
  end

  it 'preserves id types within a batch' do
    response = rpc_call([
                          { 'jsonrpc' => '2.0', 'method' => 'ping', 'id' => 'abc' },
                          { 'jsonrpc' => '2.0', 'method' => 'ping', 'id' => 9 },
                          { 'jsonrpc' => '2.0', 'method' => 'ping', 'id' => nil }
                        ])
    assert_equal 'abc', response[0]['id']
    assert_equal 9, response[1]['id']
    assert_nil response[2]['id']
    assert response[2].key?('id')
  end

  it 'responds with 204 when a batch contains only notifications' do
    response = rpc_call([
                          { 'jsonrpc' => '2.0', 'method' => 'ping' },
                          { 'jsonrpc' => '2.0', 'method' => 'explode' }
                        ])
    assert_nil response
    assert_equal 204, last_response.status
  end

  it 'keeps the registry explicit and inspectable' do
    assert_equal %w[add greet ping fail explode], app.json_rpc_methods.names
  end
end
