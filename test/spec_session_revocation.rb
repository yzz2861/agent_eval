# frozen_string_literal: true

require_relative 'helper'

require 'rack/lint'
require 'rack/mock'
require 'rack/response'
require 'securerandom'
require 'thread'

require_relative '../lib/rack/session'

describe Rack::Session::Revocation::MemoryStore do
  it 'defaults to generation zero and bumps atomically' do
    store = Rack::Session::Revocation::MemoryStore.new

    store.generation('user').must_equal 0
    store.bump_generation!('user').must_equal 1
    store.bump_generation!('user').must_equal 2
    store.generation('other').must_equal 0
  end

  it 'supports the revoke alias' do
    store = Rack::Session::Revocation::MemoryStore.new

    store.revoke!('user').must_equal 1
    store.generation('user').must_equal 1
  end
end

describe Rack::Session::Cookie do
  it 'requires encrypted or integrity-protected cookies for revocation' do
    store = Rack::Session::Revocation::MemoryStore.new

    lambda do
      Rack::Session::Cookie.new(
        lambda { |_| [200, {}, []] },
        coder: Rack::Session::Cookie::Identity.new,
        revocation_store: store
      )
    end.must_raise ArgumentError
  end
end

[Rack::Session::Cookie, Rack::Session::Pool].each do |klass|
  describe "#{klass} subject revocation" do
    def build_app(klass, store: nil, secret: SecureRandom.random_bytes(64))
      store ||= Rack::Session::Revocation::MemoryStore.new
      enter_barrier = Queue.new
      release_barrier = Queue.new

      app = lambda do |env|
        session = env['rack.session']

        case env['PATH_INFO']
        when '/guest'
          session['guest'] = true
        when '/login'
          session['user_id'] = env['QUERY_STRING'].split('=').last
        when '/logout'
          session.clear
          session.options[:renew] = true
        when '/renew'
          session.options[:renew] = true
        when '/slow-renew'
          session['touched'] = true
          enter_barrier << true
          release_barrier.pop
          session.options[:renew] = true
        end

        Rack::Response.new(session.to_hash.inspect).to_a
      end

      options = { revocation_store: store }
      options[:secrets] = secret if klass == Rack::Session::Cookie

      session_app = klass.new(app, options)
      request = Rack::MockRequest.new(Rack::Lint.new(session_app))
      barriers = { enter: enter_barrier, release: release_barrier }
      [request, store, session_app, secret, barriers]
    end

    def session_id(klass, app, cookie)
      return nil unless cookie

      raw_id = cookie[/rack\.session=([^;,]+)/, 1]

      if klass == Rack::Session::Cookie
        response = app.get('/session-id', 'HTTP_COOKIE' => cookie)
        response.body[/"session_id"\s*=>\s*"([^"]+)"/, 1]
      else
        raw_id
      end
    end

    def get(request, path, cookie = nil)
      options = cookie ? { 'HTTP_COOKIE' => cookie } : {}
      request.get(path, options)
    end

    def payload(response)
      response.body.gsub(/\s*=>\s*/, '=>')
    end

    it 'stamps new logins and leaves anonymous sessions without generation metadata' do
      request, store, = build_app(klass)

      anonymous = get(request, '/guest')
      anonymous.body.wont_include 'session_generation'

      login = get(request, '/login?user_id=1', anonymous['Set-Cookie'])
      body = payload(login)
      body.must_include '"user_id"=>"1"'
      payload(get(request, '/', login['Set-Cookie'])).must_include '"session_generation"=>0'
    end

    it 'rejects old generations after a subject is revoked' do
      request, store, = build_app(klass)

      login = get(request, '/login?user_id=1')
      cookie = login['Set-Cookie']

      payload(get(request, '/', cookie)).must_include '"user_id"=>"1"'

      store.bump_generation!('1')

      get(request, '/', cookie).body.must_equal '{}'
    end

    it 'only revokes sessions for the changed subject' do
      request, store, = build_app(klass)

      first = get(request, '/login?user_id=1')['Set-Cookie']
      second = get(request, '/login?user_id=2')['Set-Cookie']

      store.bump_generation!('1')

      get(request, '/', first).body.must_equal '{}'
      payload(get(request, '/', second)).must_include '"user_id"=>"2"'
    end

    if klass == Rack::Session::Pool
      it 'rejects malformed session generations' do
        request, store, session_app, = build_app(klass)
        cookie = get(request, '/login?user_id=1')['Set-Cookie']
        sid = Rack::Session::SessionId.new(cookie[/rack\.session=([^;,]+)/, 1])
        session_app.pool[sid.private_id]['session_generation'] = 'invalid'

        get(request, '/', cookie).body.must_equal '{}'
      end
    end

    it 'stamps the current generation when a new login changes subjects' do
      request, store, = build_app(klass)

      cookie = get(request, '/login?user_id=1')['Set-Cookie']
      store.bump_generation!('2')

      changed = get(request, '/login?user_id=2', cookie)

      body = payload(changed)
      body.must_include '"user_id"=>"2"'

      followup = get(request, '/', changed['Set-Cookie'])
      body = payload(followup)
      body.must_include '"user_id"=>"2"'
      body.must_include '"session_generation"=>1'
    end

    it 'rotates the session id on new login and logout' do
      request, store, session_app = build_app(klass)

      anonymous = get(request, '/guest')
      anonymous_cookie = anonymous['Set-Cookie']
      login = get(request, '/login?user_id=1', anonymous_cookie)
      login_cookie = login['Set-Cookie']

      session_id(klass, request, login_cookie).wont_equal(
        session_id(klass, request, anonymous_cookie)
      )

      logout = get(request, '/logout', login_cookie)
      logout.body.must_equal '{}'
      session_id(klass, request, logout['Set-Cookie']).wont_equal(
        session_id(klass, request, login_cookie)
      )
    end

    it 'does not let ordinary renewal acquire a newer generation' do
      request, store, _, _, barriers = build_app(klass)
      cookie = get(request, '/login?user_id=1')['Set-Cookie']
      slow_request = Thread.new { get(request, '/slow-renew', cookie) }
      barriers[:enter].pop

      store.bump_generation!('1')
      barriers[:release] << true
      renewed = slow_request.value

      get(request, '/', renewed['Set-Cookie']).body.must_equal '{}'
    end

    it 'fails closed when validation storage fails' do
      store = Object.new
      def store.generation(subject)
        raise Rack::Session::Revocation::StorageError, 'storage unavailable' if @failing && subject == '1'
        0
      end
      def store.bump_generation!(subject); end
      def store.fail!
        @failing = true
      end

      request, _, = build_app(klass, store: store)
      cookie = get(request, '/login?user_id=1')['Set-Cookie']
      store.fail!

      lambda { get(request, '/', cookie) }.must_raise(
        Rack::Session::Revocation::StorageError
      )
    end

    it 'fails closed when issuing storage fails' do
      store = Object.new
      def store.generation(subject)
        raise Rack::Session::Revocation::StorageError, 'storage unavailable' if subject == '1'
        0
      end
      def store.bump_generation!(subject); end

      request, _, = build_app(klass, store: store)

      lambda { get(request, '/login?user_id=1') }.must_raise(
        Rack::Session::Revocation::StorageError
      )
    end
  end
end
