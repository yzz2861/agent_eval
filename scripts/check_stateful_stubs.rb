#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone verification for the Faraday test adapter stateful stubs:
# named states, one-time transitions, session values, per-stage responses
# for the same URL, concurrency safety and backwards compatibility.
#
# Run with:
#   bundle exec ruby scripts/check_stateful_stubs.rb

require 'json'
require 'thread'
require_relative '../lib/faraday'

class Checker
  SequenceError = Faraday::Adapter::Test::Stubs::SequenceError

  attr_reader :passed

  def initialize
    @passed = 0
  end

  def check(description)
    yield
    @passed += 1
    puts "ok #{@passed} - #{description}"
  rescue StandardError => e
    warn "not ok - #{description}\n  #{e.class}: #{e.message}"
    warn e.backtrace.first(5).map { |line| "  #{line}" }.join("\n")
    exit 1
  end

  def assert_equal(expected, actual)
    raise "expected #{expected.inspect}, got #{actual.inspect}" unless expected == actual
  end

  def assert_match(pattern, string)
    raise "expected #{string.inspect} to match #{pattern.inspect}" unless pattern.match?(string)
  end

  def expect_sequence_error
    yield
    raise 'expected SequenceError'
  rescue SequenceError => e
    e
  end

  def build_stubs
    Faraday::Adapter::Test::Stubs.new do |stubs|
      stubs.get('/ping') { [200, {}, 'pong'] }

      stubs.state_machine(initial: :drafting) do |fsm|
        fsm.state :drafting do |state|
          state.post('/drafts') do |env, session|
            payload = JSON.parse(env[:body])
            session[:draft_id] = payload.fetch('id')
            [201, { 'X-Draft-Id' => session[:draft_id] }, 'draft']
          end

          state.transition(
            :post, '/submit', :submitting,
            guard: ->(env) { env.request_headers['X-Draft-Id'] }
          ) do |_env, session|
            [202, {}, "submitted:#{session[:draft_id]}"]
          end

          # Same URL as in :done, different response in this stage.
          state.get('/status') { [200, {}, 'not-started'] }
        end

        fsm.state :submitting do |state|
          state.transition(:get, '/status', :done) do |_env, session|
            [200, {}, "processing:#{session[:draft_id]}"]
          end
        end

        fsm.state :done do |state|
          state.get('/status') { [200, {}, 'done'] }
          state.get(%r{\A/drafts/(?<id>\w+)\z}) do |env, session|
            [200, {}, "draft:#{session[:draft_id]}:#{env[:method]}"]
          end
        end
      end
    end
  end
end

checker = Checker.new

checker.check 'regular stateless stubs keep matching independently of state' do
  stubs = checker.build_stubs
  conn = Faraday.new { |builder| builder.adapter :test, stubs }

  checker.assert_equal('pong', conn.get('/ping').body)
  checker.assert_equal('pong', conn.get('/ping').body)
end

checker.check 'draft -> submit -> result works in order and carries session values' do
  stubs = checker.build_stubs
  conn = Faraday.new { |builder| builder.adapter :test, stubs }

  draft = conn.post('/drafts', JSON.dump('id' => 7), 'Content-Type' => 'application/json')
  checker.assert_equal(201, draft.status)
  checker.assert_equal(7, draft.headers['X-Draft-Id'])

  submitted = conn.post('/submit') { |env| env.headers['X-Draft-Id'] = '7' }
  checker.assert_equal('submitted:7', submitted.body)

  checker.assert_equal('processing:7', conn.get('/status').body)
  checker.assert_equal('done', conn.get('/status').body)
  checker.assert_equal('draft:7:get', conn.get('/drafts/7').body)
end

checker.check 'same URL yields different responses per stage' do
  stubs = checker.build_stubs
  conn = Faraday.new { |builder| builder.adapter :test, stubs }

  checker.assert_equal('not-started', conn.get('/status').body)
  conn.post('/drafts', JSON.dump('id' => 1))
  conn.post('/submit') { |env| env.headers['X-Draft-Id'] = '1' }
  checker.assert_equal('processing:1', conn.get('/status').body)
  checker.assert_equal('done', conn.get('/status').body)
end

checker.check 'a transition whose guard fails is not consumed and later succeeds' do
  stubs = checker.build_stubs
  conn = Faraday.new { |builder| builder.adapter :test, stubs }

  conn.post('/drafts', JSON.dump('id' => 3))
  checker.expect_sequence_error { conn.post('/submit') }
  response = conn.post('/submit') { |env| env.headers['X-Draft-Id'] = '3' }
  checker.assert_equal('submitted:3', response.body)
end

checker.check 'reaching a later-stage route before prior steps raises a clear SequenceError' do
  stubs = checker.build_stubs
  conn = Faraday.new { |builder| builder.adapter :test, stubs }

  error = checker.expect_sequence_error { conn.get('/drafts/9') }
  checker.assert_match(%r{GET .*drafts/9}, error.message)
  checker.assert_match(/drafting/, error.message)
end

checker.check 'competing requests for a one-time transition have exactly one winner' do
  stubs = checker.build_stubs
  conn = Faraday.new { |builder| builder.adapter :test, stubs }
  conn.post('/drafts', JSON.dump('id' => 5))

  gate = Queue.new
  threads = Array.new(8) do
    Thread.new do
      gate.pop
      begin
        conn.post('/submit') { |env| env.headers['X-Draft-Id'] = '5' }
        :ok
      rescue Faraday::Adapter::Test::Stubs::SequenceError
        :sequence_error
      end
    end
  end

  8.times { gate << :go }
  checker.assert_equal({ ok: 1, sequence_error: 7 }, threads.map(&:value).tally)

  error = checker.expect_sequence_error do
    conn.post('/submit') { |env| env.headers['X-Draft-Id'] = '5' }
  end
  checker.assert_match(/already been taken/, error.message)
end

checker.check 'verify_stubbed_calls reports unconsumed workflow transitions' do
  stubs = checker.build_stubs
  error = begin
    stubs.verify_stubbed_calls
    nil
  rescue RuntimeError => e
    e
  end
  raise 'expected verification error' if error.nil?
  checker.assert_match(%r{/submit}, error.message)
end

puts "\n#{checker.passed} checks passed"
