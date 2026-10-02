# frozen_string_literal: true
require 'support'
require 'mustermann/router'

describe Mustermann::Router do
  def env(method: 'GET', path: '/')
    { 'REQUEST_METHOD' => method, 'PATH_INFO' => path }
  end

  # ── NOT_FOUND constant ─────────────────────────────────────────────────────

  describe 'NOT_FOUND' do
    it 'is a 404 with X-Cascade: pass' do
      router = described_class.new
      status, headers, = router.call(env(path: '/missing'))
      expect(status).to eq 404
      expect(headers['x-cascade']).to eq 'pass'
    end

    it 'is frozen' do
      not_found = Mustermann::Router.send(:const_get, :NOT_FOUND)
      expect(not_found).to be_frozen
    end
  end

  # ── basic routing ──────────────────────────────────────────────────────────

  context 'basic routing' do
    subject(:router) do
      described_class.new do
        get('/hello') { |_env| [200, {}, ['hello']] }
      end
    end

    it 'routes a matching GET request' do
      status, = router.call(env(path: '/hello'))
      expect(status).to eq 200
    end

    it 'returns 404 for a non-matching path' do
      status, = router.call(env(path: '/goodbye'))
      expect(status).to eq 404
    end

    it 'returns 404 for the wrong HTTP method' do
      status, = router.call(env(method: 'POST', path: '/hello'))
      expect(status).to eq 404
    end
  end

  # ── match stored in env ────────────────────────────────────────────────────

  context 'match stored in env' do
    it 'stores the match in env["mustermann.match"] by default' do
      router = described_class.new do
        get('/:name') { |e| [200, {}, [e['mustermann.match'][:name]]] }
      end
      _, _, body = router.call(env(path: '/alice'))
      expect(body).to eq ['alice']
    end

    it 'exposes params from the match' do
      captured = nil
      router = described_class.new do
        get('/:id') { |e| captured = e['mustermann.match'].params; [200, {}, []] }
      end
      router.call(env(path: '/42'))
      expect(captured).to eq('id' => '42')
    end

    it 'uses a custom key when specified' do
      router = described_class.new(key: 'my.match') do
        get('/:x') { |e| [200, {}, [e['my.match'][:x]]] }
      end
      _, _, body = router.call(env(path: '/world'))
      expect(body).to eq ['world']
    end

    it 'stores the match in the env hash' do
      router = described_class.new do
        get('/foo') { |_e| [200, {}, []] }
      end
      original = env(path: '/foo')
      router.call(original)
      expect(original).to have_key('mustermann.match')
    end
  end

  # ── fallback ───────────────────────────────────────────────────────────────

  context 'fallback' do
    it 'uses the default NOT_FOUND when no fallback is given' do
      router = described_class.new
      status, headers, = router.call(env)
      expect(status).to eq 404
      expect(headers['x-cascade']).to eq 'pass'
    end

    it 'returns a mutable response from the default fallback so middleware can modify it' do
      router = described_class.new
      response = router.call(env(path: '/missing'))
      expect(response).not_to be_frozen
    end

    it 'accepts a callable as the first positional argument' do
      custom = ->(_env) { [503, {}, ['down']] }
      router = described_class.new(custom)
      status, _, body = router.call(env)
      expect(status).to eq 503
      expect(body).to eq ['down']
    end

    it 'accepts a callable via #fallback' do
      router = described_class.new
      router.fallback ->(_env) { [410, {}, ['gone']] }
      status, = router.call(env)
      expect(status).to eq 410
    end

    it 'accepts a block via #fallback' do
      router = described_class.new
      router.fallback { |_env| [418, {}, ["I'm a teapot"]] }
      status, = router.call(env)
      expect(status).to eq 418
    end
  end

  # ── HTTP verb shorthand methods ────────────────────────────────────────────

  context 'HTTP verb shorthand methods' do
    %w[GET POST PUT PATCH DELETE OPTIONS LINK UNLINK].each do |verb|
      it "defines ##{verb.downcase} routing" do
        router = described_class.new
        router.send(verb.downcase, '/test') { |_env| [200, {}, [verb]] }
        status, _, body = router.call(env(method: verb, path: '/test'))
        expect(status).to eq 200
        expect(body).to eq [verb]
      end
    end
  end

  # ── #route method ──────────────────────────────────────────────────────────

  context '#route' do
    it 'adds a route with a block' do
      router = described_class.new
      router.route('GET', '/ping') { |_env| [200, {}, ['pong']] }
      _, _, body = router.call(env(path: '/ping'))
      expect(body).to eq ['pong']
    end

    it 'adds a route with a callable target' do
      app = ->(_env) { [200, {}, ['app']] }
      router = described_class.new
      router.route('POST', '/submit', app)
      _, _, body = router.call(env(method: 'POST', path: '/submit'))
      expect(body).to eq ['app']
    end

    it 'raises ArgumentError for an unknown verb' do
      router = described_class.new
      expect { router.route('BREW', '/coffee') { } }.to raise_error(ArgumentError, /unknown verb/)
    end

    it 'raises ArgumentError when neither target nor block is given' do
      router = described_class.new
      expect { router.route('GET', '/foo') }.to raise_error(ArgumentError, /target/)
    end
  end

  # ── DSL block at construction ──────────────────────────────────────────────

  context 'DSL block at construction' do
    it 'evaluates the block in router context' do
      router = described_class.new do
        get('/a') { |_| [200, {}, ['a']] }
        post('/b') { |_| [201, {}, ['b']] }
      end
      expect(router.call(env(path: '/a')).first).to eq 200
      expect(router.call(env(method: 'POST', path: '/b')).first).to eq 201
    end
  end

  # ── pattern options ────────────────────────────────────────────────────────

  context 'pattern options' do
    it 'forwards options to Mustermann (e.g. type: :rails)' do
      router = described_class.new(type: :rails) do
        get('/:id(.:format)') { |e| [200, {}, [e['mustermann.match'][:id]]] }
      end
      status, _, body = router.call(env(path: '/42.json'))
      expect(status).to eq 200
      expect(body).to eq ['42']
    end
  end

  # ── #path_for URL generation ───────────────────────────────────────────────

  context '#path_for' do
    it 'generates a path for a registered handler' do
      target = ->(_env) { [200, {}, []] }
      router = described_class.new do
        get '/users/:id', target
      end
      expect(router.path_for(target, id: '5')).to eq '/users/5'
    end

    it 'generates a path searching across all verbs' do
      target = ->(_env) { [200, {}, []] }
      router = described_class.new do
        delete '/posts/:slug', target
      end
      expect(router.path_for(target, slug: 'hello')).to eq '/posts/hello'
    end
  end

  # ── middleware usage ───────────────────────────────────────────────────────

  context 'middleware usage' do
    it 'passes unmatched requests to the inner app (first positional arg)' do
      inner = ->(_env) { [200, {}, ['inner']] }
      router = described_class.new(inner) do
        get('/handled') { |_| [200, {}, ['handled']] }
      end
      _, _, body = router.call(env(path: '/unhandled'))
      expect(body).to eq ['inner']
    end

    it 'does not call the inner app for matched routes' do
      inner = ->(_env) { raise 'should not be called' }
      router = described_class.new(inner) do
        get('/handled') { |_| [200, {}, ['handled']] }
      end
      expect { router.call(env(path: '/handled')) }.not_to raise_error
    end
  end

  # ── strict_order option ────────────────────────────────────────────────────

  context 'strict_order option' do
    it 'forwards strict_order: true to each underlying set' do
      router = described_class.new(strict_order: true)
      sets = router.instance_variable_get(:@sets)
      expect(sets.values).to all(satisfy(&:strict_order?))
    end

    it 'defaults to strict_order: false on each underlying set' do
      router = described_class.new
      sets = router.instance_variable_get(:@sets)
      expect(sets.values).to all(satisfy { |s| !s.strict_order? })
    end

    it 'dispatches in insertion order when strict_order: true' do
      matched = nil
      dynamic_handler = ->(_env) { matched = :dynamic; [200, {}, []] }
      static_handler  = ->(_env) { matched = :static;  [200, {}, []] }

      # use_trie: true forces the trie, which would normally prefer the static
      # route over the dynamic one — strict_order must override that.
      router = described_class.new(strict_order: true, use_trie: true) do
        get('/:path',  dynamic_handler)
        get('/static', static_handler)
      end

      router.call(env(path: '/static'))
      expect(matched).to eq :dynamic
    end

    it 'prefers static routes over dynamic without strict_order (trie default behavior)' do
      matched = nil
      dynamic_handler = ->(_env) { matched = :dynamic; [200, {}, []] }
      static_handler  = ->(_env) { matched = :static;  [200, {}, []] }

      router = described_class.new(use_trie: true) do
        get('/:path',  dynamic_handler)
        get('/static', static_handler)
      end

      router.call(env(path: '/static'))
      expect(matched).to eq :static
    end
  end

  # ── method_negotiation option ──────────────────────────────────────────────

  context 'method_negotiation: true' do
    subject(:router) do
      described_class.new(method_negotiation: true) do
        get('/users')       { |_env| [200, { 'content-type' => 'text/plain' }, ['users']] }
        post('/users')      { |_env| [201, {}, ['created']] }
        delete('/users/:id') { |_env| [204, {}, []] }
        head('/head-only')  { |_env| [200, { 'x-head' => 'yes' }, ['should not be sent']] }
        options('/custom')  { |_env| [200, { 'x-custom' => 'yes' }, ['custom']] }
      end
    end

    describe '405 vs 404' do
      it 'returns 405 with an accurate Allow header when the path exists but the method is unsupported' do
        status, headers, body = router.call(env(method: 'DELETE', path: '/users'))
        expect(status).to eq 405
        expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
        expect(body).to eq ['Method Not Allowed']
      end

      it 'only lists verbs registered for that exact path' do
        status, headers, = router.call(env(method: 'PUT', path: '/users/42'))
        expect(status).to eq 405
        expect(headers['allow'].split(', ')).to contain_exactly('DELETE', 'OPTIONS')
      end

      it 'returns 404 through the fallback for an unknown path' do
        status, headers, = router.call(env(method: 'POST', path: '/nope'))
        expect(status).to eq 404
        expect(headers).to have_key('x-cascade')
        expect(headers).not_to have_key('allow')
      end

      it 'returns 404 for an unknown method on an unknown path rather than 405' do
        status, = router.call(env(method: 'BREW', path: '/nope'))
        expect(status).to eq 404
      end

      it 'returns 405 for an unknown method on a known path' do
        status, headers, = router.call(env(method: 'BREW', path: '/users'))
        expect(status).to eq 405
        expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
      end

      it 'does not route the method-mismatch request to the fallback app' do
        fallback_calls = 0
        router = described_class.new(->(_env) { fallback_calls += 1; [404, {}, ['nope']] },
                                    method_negotiation: true) do
          get('/users') { [200, {}, ['users']] }
        end
        status, = router.call(env(method: 'POST', path: '/users'))
        expect(status).to eq 405
        expect(fallback_calls).to eq 0
      end

      it 'uses the fallback for unknown paths' do
        router = described_class.new(->(_env) { [418, {}, ['teapot']] }, method_negotiation: true) do
          get('/users') { [200, {}, ['users']] }
        end
        expect(router.call(env(method: 'POST', path: '/nope')).first).to eq 418
      end
    end

    describe 'Allow header ordering' do
      it 'follows a canonical method order' do
        router = described_class.new(method_negotiation: true) do
          unlink('/r') { [200, {}, []] }
          link('/r')   { [200, {}, []] }
          post('/r')   { [200, {}, []] }
        end
        _, headers, = router.call(env(method: 'PUT', path: '/r'))
        expect(headers['allow']).to eq 'POST, OPTIONS, LINK, UNLINK'
      end
    end

    describe 'HEAD handling' do
      it 'prefers an explicit HEAD route over GET' do
        status, headers, body = router.call(env(method: 'HEAD', path: '/head-only'))
        expect(status).to eq 200
        expect(headers['x-head']).to eq 'yes'
        expect(body).to eq []
      end

      it 'falls back to the GET route when no explicit HEAD route exists' do
        status, headers, body = router.call(env(method: 'HEAD', path: '/users'))
        expect(status).to eq 200
        expect(headers['content-type']).to eq 'text/plain'
        expect(body).to eq []
      end

      it 'prefers the explicit HEAD route even when a GET route exists on the same path' do
        picked = []
        router = described_class.new(method_negotiation: true) do
          get('/both')  { |_env| picked << :get;  [200, {}, ['get']] }
          head('/both') { |_env| picked << :head; [200, { 'x-via' => 'head' }, ['head']] }
        end
        status, headers, body = router.call(env(method: 'HEAD', path: '/both'))
        expect(status).to eq 200
        expect(headers['x-via']).to eq 'head'
        expect(body).to eq []
        expect(picked).to eq [:head]
      end

      it 'returns 405 for HEAD when the path only supports other methods' do
        status, headers, body = router.call(env(method: 'HEAD', path: '/users/42'))
        expect(status).to eq 405
        expect(headers['allow'].split(', ')).to contain_exactly('DELETE', 'OPTIONS')
        expect(body).to eq ['Method Not Allowed']
      end

      def closeable_body(times)
        body = Object.new
        def body.each; end
        body.define_singleton_method(:close) { times << :close }
        body
      end

      it 'calls the GET target exactly once and closes the returned body' do
        calls  = []
        app    = ->(_env) { calls << :call; [200, {}, closeable_body(calls)] }
        router = described_class.new(method_negotiation: true) do
          get('/once', app)
        end

        status, returned_headers, returned_body = router.call(env(method: 'HEAD', path: '/once'))
        expect(status).to eq 200
        expect(returned_headers).to eq({})
        expect(returned_body).to eq []
        expect(calls).to eq %i[call close]
      end

      it 'closes the body returned by an explicit HEAD target exactly once' do
        events = []
        app    = ->(_env) { events << :call; [200, { 'x-head' => 'yes' }, closeable_body(events)] }
        router = described_class.new(method_negotiation: true) do
          head('/explicit', app)
        end

        status, headers, returned_body = router.call(env(method: 'HEAD', path: '/explicit'))
        expect(status).to eq 200
        expect(headers['x-head']).to eq 'yes'
        expect(returned_body).to eq []
        expect(events).to eq %i[call close]
      end

      it 'does not close or strip bodies for non-HEAD requests' do
        closes = 0
        body = ['users']
        body.define_singleton_method(:close) { closes += 1 }
        app = ->(_env) { [200, {}, body] }
        router = described_class.new(method_negotiation: true) do
          get('/keep', app)
        end
        _, _, returned_body = router.call(env(path: '/keep'))
        expect(returned_body).to eq ['users']
        expect(closes).to eq 0
      end

      it 'passes the env match through the GET fallback route' do
        router = described_class.new(method_negotiation: true) do
          get('/users/:id') { |e| [200, {}, [e['mustermann.match'][:id]]] }
        end
        status, _, body = router.call(env(method: 'HEAD', path: '/users/99'))
        expect(status).to eq 200
        expect(body).to eq []
        expect(router.call(env(path: '/users/99')).last).to eq ['99']
      end

      it 'honors a custom env key for the match' do
        router = described_class.new(method_negotiation: true, key: 'my.match') do
          get('/u/:id') { |e| [200, {}, [e['my.match'][:id]]] }
        end
        expect(router.call(env(path: '/u/7')).last).to eq ['7']
        expect(router.call(env(method: 'HEAD', path: '/u/7')).last).to eq []
      end

    end

    describe 'automatic OPTIONS' do
      it 'answers OPTIONS automatically with the allowed methods and an empty body' do
        status, headers, body = router.call(env(method: 'OPTIONS', path: '/users'))
        expect(status).to eq 200
        expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
        expect(body).to eq []
      end

      it 'uses the same candidate rules as 405 for a parameterized path' do
        _, headers, = router.call(env(method: 'OPTIONS', path: '/users/7'))
        expect(headers['allow'].split(', ')).to contain_exactly('DELETE', 'OPTIONS')
      end

      it 'prefers an explicit OPTIONS route over the automatic response' do
        status, headers, body = router.call(env(method: 'OPTIONS', path: '/custom'))
        expect(status).to eq 200
        expect(headers['x-custom']).to eq 'yes'
        expect(body).to eq ['custom']
      end

      it 'falls through to the fallback for OPTIONS on an unknown path' do
        status, headers, = router.call(env(method: 'OPTIONS', path: '/nope'))
        expect(status).to eq 404
        expect(headers).not_to have_key('allow')
      end

      it 'never invokes a target application to determine allowed methods' do
        calls = 0
        app = ->(_env) { calls += 1; [200, {}, ['x']] }
        router = described_class.new(method_negotiation: true) do
          get('/guarded', app)
        end
        router.call(env(method: 'OPTIONS', path: '/guarded'))
        router.call(env(method: 'POST', path: '/guarded'))
        expect(calls).to eq 0
      end
    end

    describe 'candidate matching' do
      it 'takes captures into account for both 405 and Allow' do
        router = described_class.new(method_negotiation: true) do
          get('/users/:id')   { [200, {}, ['show']] }
          post('/users')      { [201, {}, ['create']] }
        end
        expect(router.call(env(method: 'POST', path: '/users/42')).first).to eq 405
        expect(router.call(env(method: 'GET', path: '/users/42')).first).to eq 200
        expect(router.call(env(method: 'POST', path: '/users')).first).to eq 201
        expect(router.call(env(method: 'DELETE', path: '/users')).first).to eq 405
      end

      it 'supports several pattern types on the same path at once' do
        router = described_class.new(method_negotiation: true, type: :rails) do
          get('/users(/index)')   { [200, {}, ['list']] }
          post('/users(/index)')  { [201, {}, ['create']] }
        end
        expect(router.call(env(method: 'GET', path: '/users/index')).first).to eq 200
        status, headers, = router.call(env(method: 'DELETE', path: '/users'))
        expect(status).to eq 405
        expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
      end
    end

    describe 'optimized sets' do
      it 'works after optimize! (block construction)' do
        router = described_class.new(method_negotiation: true, use_trie: true) do
          get('/a') { [200, {}, ['a']] }
        end
        expect(router.call(env(method: 'POST', path: '/a')).first).to eq 405
        expect(router.call(env(method: 'HEAD', path: '/a')).first).to eq 200
        expect(router.call(env(method: 'OPTIONS', path: '/a')).first).to eq 200
      end

      it 'works with routes added after construction and manual optimize!' do
        router = described_class.new(method_negotiation: true)
        router.get('/manual') { [200, {}, ['m']] }
        router.instance_variable_get(:@sets).each_value(&:optimize!)
        status, headers, = router.call(env(method: 'PUT', path: '/manual'))
        expect(status).to eq 405
        expect(headers['allow']).to eq 'GET, HEAD, OPTIONS'
      end

      it 'negotiates correctly on a threshold-optimized trie with many routes' do
        router = described_class.new(method_negotiation: true, use_trie: 50) do
          60.times { |i| get("/item-#{i}") { [200, {}, ["item#{i}"]] } }
          post('/item-59') { [201, {}, []] }
        end
        status, headers, = router.call(env(method: 'DELETE', path: '/item-0'))
        expect(status).to eq 405
        expect(headers['allow']).to eq 'GET, HEAD, OPTIONS'
        expect(router.call(env(method: 'HEAD', path: '/item-1')).first).to eq 200
        status, headers, = router.call(env(method: 'PUT', path: '/item-59'))
        expect(status).to eq 405
        expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
        expect(router.call(env(method: 'POST', path: '/item-59')).first).to eq 201
      end
    end

    describe '#allowed_methods' do
      it 'returns the allowed verbs for a known path' do
        expect(router.allowed_methods('/users'))
          .to eq %w[GET HEAD POST OPTIONS]
      end

      it 'returns an empty array for an unknown path' do
        expect(router.allowed_methods('/nope')).to eq []
      end

      it 'lists HEAD for an explicit HEAD-only route' do
        expect(router.allowed_methods('/head-only')).to eq %w[HEAD OPTIONS]
      end
    end

    describe 'HEAD once, body closed (counting app)' do
      let(:counting_app) do
        Class.new do
          attr_reader :calls, :closed

          def initialize
            @calls  = 0
            @closed = 0
          end

          def call(_env)
            @calls += 1
            app = self
            body = Object.new
            body.define_singleton_method(:each) { }
            body.define_singleton_method(:close) { app.close! }
            [200, { 'content-type' => 'text/plain' }, body]
          end

          def close!
            @closed += 1
          end
        end
      end

      it 'invokes the target once and hands closing responsibility to the router' do
        app = counting_app.new
        router = described_class.new(method_negotiation: true) do
          get('/count', app)
        end

        status, headers, body = router.call(env(method: 'HEAD', path: '/count'))

        expect(status).to eq 200
        expect(headers['content-type']).to eq 'text/plain'
        expect(body).to eq []
        expect(app.calls).to eq 1
        expect(app.closed).to eq 1
      end
    end
  end

  # ── legacy mode stays the default ──────────────────────────────────────────

  context 'without method_negotiation (default)' do
    it 'keeps routing HEAD like GET and falling through to the fallback' do
      router = described_class.new do
        get('/users') { [200, {}, ['users']] }
      end
      expect(router.call(env(method: 'HEAD', path: '/users')).first).to eq 200
      expect(router.call(env(method: 'POST', path: '/users')).first).to eq 404
      expect(router.call(env(method: 'OPTIONS', path: '/users')).first).to eq 404
    end

    it 'does not negotiate for an explicitly registered HEAD route' do
      picked = []
      router = described_class.new do
        get('/both')  { picked << :get;  [200, {}, ['get']] }
        head('/both') { picked << :head; [200, {}, ['head']] }
      end
      status, _, body = router.call(env(method: 'HEAD', path: '/both'))
      expect(status).to eq 200
      expect(body).to eq ['get']
      expect(picked).to eq [:get]
    end
  end
end
