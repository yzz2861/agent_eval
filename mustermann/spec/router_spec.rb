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

  context 'method negotiation' do
    class CountingBody
      attr_reader :close_count, :each_count

      def initialize(chunks)
        @chunks      = chunks
        @close_count = 0
        @each_count  = 0
      end

      def each
        @each_count += 1
        @chunks.each { |chunk| yield chunk }
      end

      def close
        @close_count += 1
      end
    end

    it 'keeps the original behavior disabled by default' do
      router = described_class.new do
        get('/users') { |_env| [200, {}, ['users']] }
      end

      status, headers, = router.call(env(method: 'POST', path: '/users'))
      expect(status).to eq 404
      expect(headers).not_to have_key('allow')
    end

    it 'does not register HEAD shorthand routes unless negotiation is enabled' do
      router = described_class.new
      expect(router).not_to respond_to(:head)
      expect { router.route('HEAD', '/users') { } }.to raise_error(ArgumentError, /unknown verb: HEAD/)
    end

    it 'returns 405 with the supported methods for a known path' do
      calls = Hash.new(0)
      router = described_class.new(method_negotiation: true) do
        get('/users') { |_env| calls[:get] += 1; [200, {}, ['users']] }
        post('/users') { |_env| calls[:post] += 1; [201, {}, []] }
      end

      status, headers, body = router.call(env(method: 'PUT', path: '/users'))
      expect(status).to eq 405
      expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
      expect(body).to eq ['Method not allowed']
      expect(calls).to be_empty
    end

    it 'keeps unknown paths on the fallback' do
      fallback_calls = 0
      fallback = ->(_env) { fallback_calls += 1; [404, {}, ['missing']] }
      router = described_class.new(fallback, method_negotiation: true) do
        get('/users') { |_env| [200, {}, ['users']] }
      end

      status, _, body = router.call(env(method: 'PUT', path: '/unknown'))
      expect(status).to eq 404
      expect(body).to eq ['missing']
      expect(fallback_calls).to eq 1
    end

    it 'does not use fallback when a path exists but the method does not' do
      fallback_calls = 0
      fallback = ->(_env) { fallback_calls += 1; [404, {}, []] }
      router = described_class.new(fallback, method_negotiation: true) do
        post('/users') { |_env| [201, {}, []] }
      end

      status, = router.call(env(method: 'DELETE', path: '/users'))
      expect(status).to eq 405
      expect(fallback_calls).to eq 0
    end

    it 'answers OPTIONS automatically from the matching candidate rules' do
      calls = Hash.new(0)
      router = described_class.new(method_negotiation: true) do
        get('/users(.:format)') { |_env| calls[:get] += 1; [200, {}, ['users']] }
        post('/users.json') { |_env| calls[:post] += 1; [201, {}, []] }
      end

      status, headers, body = router.call(env(method: 'OPTIONS', path: '/users.json'))
      expect(status).to eq 200
      expect(headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
      expect(body).to eq []
      expect(calls).to be_empty
    end

    it 'keeps unknown OPTIONS paths on the fallback' do
      router = described_class.new(method_negotiation: true) do
        get('/users') { |_env| [200, {}, []] }
      end

      status, headers, = router.call(env(method: 'OPTIONS', path: '/unknown'))
      expect(status).to eq 404
      expect(headers['x-cascade']).to eq 'pass'
    end

    it 'prefers an explicit OPTIONS route' do
      router = described_class.new(method_negotiation: true) do
        get('/users') { |_env| [200, {}, []] }
        options('/users') { |_env| [200, { 'x-custom' => 'yes' }, []] }
      end

      status, headers, = router.call(env(method: 'OPTIONS', path: '/users'))
      expect(status).to eq 200
      expect(headers['x-custom']).to eq 'yes'
      expect(headers['allow']).to be_nil
    end

    it 'prefers an explicit HEAD route and calls its application once' do
      head_body = CountingBody.new(['head'])
      get_body  = CountingBody.new(['get'])
      head_calls = 0
      get_calls  = 0
      router = described_class.new(method_negotiation: true) do
        head('/users') { |_env| head_calls += 1; [200, {}, head_body] }
        get('/users') { |_env| get_calls += 1; [200, {}, get_body] }
      end

      status, headers, body = router.call(env(method: 'HEAD', path: '/users'))
      chunks = []
      body.each { |chunk| chunks << chunk }
      body.close

      expect(status).to eq 200
      expect(headers).to eq({})
      expect(chunks).to eq []
      expect(head_calls).to eq 1
      expect(get_calls).to eq 0
      expect(head_body.close_count).to eq 1
      expect(get_body.close_count).to eq 0
    end

    it 'falls back to GET for HEAD and calls the application once without a body' do
      body = CountingBody.new(['users'])
      calls = 0
      app = ->(_env) do
        calls += 1
        [200, { 'content-length' => '5', 'x-test' => 'yes' }, body]
      end
      router = described_class.new(method_negotiation: true) do
        get('/users', app)
        post('/users') { |_env| [201, {}, []] }
      end

      status, headers, response_body = router.call(env(method: 'HEAD', path: '/users'))
      chunks = []
      response_body.each { |chunk| chunks << chunk }
      response_body.close
      response_body.close

      expect(status).to eq 200
      expect(headers['content-length']).to eq '5'
      expect(headers['x-test']).to eq 'yes'
      expect(chunks).to eq []
      expect(calls).to eq 1
      expect(body.each_count).to eq 0
      expect(body.close_count).to eq 1
    end

    it 'returns 405 for HEAD when the path only supports other methods' do
      router = described_class.new(method_negotiation: true) do
        post('/users') { |_env| [201, {}, []] }
      end

      status, headers, = router.call(env(method: 'HEAD', path: '/users'))
      expect(status).to eq 405
      expect(headers['allow']).to eq 'POST, OPTIONS'
    end

    it 'works after manual optimization' do
      router = described_class.new(method_negotiation: true)
      router.get('/users(.:format)') { |_env| [200, {}, ['users']] }
      router.post('/users.json') { |_env| [201, {}, []] }
      router.instance_variable_get(:@sets).each_value(&:optimize!)

      options_status, options_headers, = router.call(env(method: 'OPTIONS', path: '/users.json'))
      wrong_status, wrong_headers, = router.call(env(method: 'PUT', path: '/users.json'))
      unknown_status, = router.call(env(method: 'PUT', path: '/nope'))

      expect(options_status).to eq 200
      expect(options_headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
      expect(wrong_status).to eq 405
      expect(wrong_headers['allow']).to eq 'GET, HEAD, POST, OPTIONS'
      expect(unknown_status).to eq 404
    end
  end
end
