# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.
# Copyright, 2022, by Jeremy Evans.

require_relative 'helper'
require 'rack/response'
require 'rack/lint'
require 'rack/mock'
require 'rack/urlmap'
require 'json'

require_relative '../lib/rack/session/cookie'

describe Rack::Session::Cookie do
  incrementor = lambda do |env|
    env["rack.session"]["counter"] ||= 0
    env["rack.session"]["counter"] += 1
    hash = env["rack.session"].dup
    hash.delete("session_id")
    Rack::Response.new(hash.inspect).to_a
  end

  session_id = lambda do |env|
    Rack::Response.new(env["rack.session"].to_hash.inspect).to_a
  end

  session_option = lambda do |opt|
    lambda do |env|
      Rack::Response.new(env["rack.session.options"][opt].inspect).to_a
    end
  end

  nothing = lambda do |env|
    Rack::Response.new("Nothing").to_a
  end

  renewer = lambda do |env|
    env["rack.session.options"][:renew] = true
    Rack::Response.new("Nothing").to_a
  end

  only_session_id = lambda do |env|
    Rack::Response.new(env["rack.session"]["session_id"].to_s).to_a
  end

  bigcookie = lambda do |env|
    env["rack.session"]["cookie"] = "big" * 3000
    Rack::Response.new(env["rack.session"].inspect).to_a
  end

  destroy_session = lambda do |env|
    env["rack.session"].destroy
    Rack::Response.new("Nothing").to_a
  end

  def response_for(options = {})
    request_options = options.fetch(:request, {})
    cookie = if options[:cookie].is_a?(Rack::Response)
      options[:cookie]["Set-Cookie"]
    else
      options[:cookie]
    end
    request_options["HTTP_COOKIE"] = cookie || ""

    app_with_cookie = Rack::Session::Cookie.new(*options[:app])
    app_with_cookie = Rack::Lint.new(app_with_cookie)
    Rack::MockRequest.new(app_with_cookie).get("/", request_options)
  end

  def random_encryptor_secret
    SecureRandom.random_bytes(64)
  end

  before do
    # Random key, as a hex string
    @secret = random_encryptor_secret

    @warnings = warnings = []
    Rack::Session::Cookie.class_eval do
      define_method(:warn) { |m| warnings << m }
    end
  end

  after do
    Rack::Session::Cookie.class_eval { remove_method :warn }
  end

  describe 'Base64' do
    it 'uses base64 to encode' do
      coder = Rack::Session::Cookie::Base64.new
      str   = 'fuuuuu'
      coder.encode(str).must_equal [str].pack('m0')
    end

    it 'uses base64 to decode' do
      coder = Rack::Session::Cookie::Base64.new
      str   = ['fuuuuu'].pack('m0')
      coder.decode(str).must_equal str.unpack('m0').first
    end

    it 'handles non-strict base64 encoding' do
      coder = Rack::Session::Cookie::Base64.new
      str   = ['A' * 256].pack('m')
      coder.decode(str).must_equal 'A' * 256
    end

    describe 'Marshal' do
      it 'marshals and base64 encodes' do
        coder = Rack::Session::Cookie::Base64::Marshal.new
        str   = 'fuuuuu'
        coder.encode(str).must_equal [::Marshal.dump(str)].pack('m0')
      end

      it 'marshals and base64 decodes' do
        coder = Rack::Session::Cookie::Base64::Marshal.new
        str   = [::Marshal.dump('fuuuuu')].pack('m0')
        coder.decode(str).must_equal ::Marshal.load(str.unpack('m0').first)
      end

      it 'rescues failures on decode' do
        coder = Rack::Session::Cookie::Base64::Marshal.new
        coder.decode('lulz').must_be_nil
      end
    end

    describe 'JSON' do
      it 'JSON and base64 encodes' do
        coder = Rack::Session::Cookie::Base64::JSON.new
        obj   = %w[fuuuuu]
        coder.encode(obj).must_equal [::JSON.dump(obj)].pack('m0')
      end

      it 'JSON and base64 decodes' do
        coder = Rack::Session::Cookie::Base64::JSON.new
        str   = [::JSON.dump(%w[fuuuuu])].pack('m0')
        coder.decode(str).must_equal ::JSON.parse(str.unpack('m0').first)
      end

      it 'rescues failures on decode' do
        coder = Rack::Session::Cookie::Base64::JSON.new
        coder.decode('lulz').must_be_nil
      end
    end

    describe 'ZipJSON' do
      it 'jsons, deflates, and base64 encodes' do
        coder = Rack::Session::Cookie::Base64::ZipJSON.new
        obj   = %w[fuuuuu]
        json = JSON.dump(obj)
        coder.encode(obj).must_equal [Zlib::Deflate.deflate(json)].pack('m0')
      end

      it 'base64 decodes, inflates, and decodes json' do
        coder = Rack::Session::Cookie::Base64::ZipJSON.new
        obj   = %w[fuuuuu]
        json  = JSON.dump(obj)
        b64   = [Zlib::Deflate.deflate(json)].pack('m0')
        coder.decode(b64).must_equal obj
      end

      it 'rescues failures on decode' do
        coder = Rack::Session::Cookie::Base64::ZipJSON.new
        coder.decode('lulz').must_be_nil
      end
    end
  end

  it "warns if no secret is given" do
    Rack::Session::Cookie.new(incrementor)
    @warnings.first.must_match(/no secret/i)
    @warnings.clear
    Rack::Session::Cookie.new(incrementor, secrets: @secret)
    @warnings.must_be :empty?
  end

  it 'abort if secret is too short' do
    lambda {
      Rack::Session::Cookie.new(incrementor, secrets: @secret[0, 16])
    }.must_raise ArgumentError
  end

  it "doesn't warn if coder is configured to handle encoding" do
    Rack::Session::Cookie.new(
      incrementor,
      coder: Object.new,
      let_coder_handle_secure_encoding: true)
    @warnings.must_be :empty?
  end

  it "still warns if coder is not set" do
    Rack::Session::Cookie.new(
      incrementor,
      let_coder_handle_secure_encoding: true)
    @warnings.first.must_match(/no secret/i)
  end

  it 'uses a coder' do
    identity = Class.new {
      attr_reader :calls

      def initialize
        @calls = []
      end

      def encode(hash); @calls << :encode; hash.to_json; end
      def decode(str); @calls << :decode; JSON.parse(str); end
    }.new
    response = response_for(app: [incrementor, { coder: identity }])

    response["Set-Cookie"].must_include "rack.session="
    response.body.must_equal ({"counter"=>1}.to_s)
    identity.calls.must_equal [:encode]

    response_for(app: [incrementor, { coder: identity }], cookie: response["Set-Cookie"].split(';', 2).first)
    identity.calls.must_equal [:encode, :decode, :encode]
  end

  it "creates a new cookie" do
    response = response_for(app: incrementor)
    response["Set-Cookie"].must_include "rack.session="
    response.body.must_equal ({"counter"=>1}.to_s)
  end

  it "passes through same_site option to session cookie" do
    response = response_for(app: [incrementor, same_site: :none])
    response["Set-Cookie"].must_match /SameSite=None/i
  end

  it "allows using a lambda to specify same_site option, because some browsers require different settings" do
    # Details of why this might need to be set dynamically:
    # https://www.chromium.org/updates/same-site/incompatible-clients
    # https://gist.github.com/bnorton/7dee72023787f367c48b3f5c2d71540f

    response = response_for(app: [incrementor, same_site: lambda { |req, res| :none }])
    response["Set-Cookie"].must_match /SameSite=None/i

    response = response_for(app: [incrementor, same_site: lambda { |req, res| :lax }])
    response["Set-Cookie"].must_match /SameSite=Lax/i
  end

  it "loads from a cookie" do
    response = response_for(app: incrementor)

    response = response_for(app: incrementor, cookie: response)
    response.body.must_equal ({"counter"=>2}.to_s)

    response = response_for(app: incrementor, cookie: response)
    response.body.must_equal ({"counter"=>3}.to_s)
  end

  it "renew session id" do
    response = response_for(app: incrementor)
    cookie   = response['Set-Cookie']
    response = response_for(app: only_session_id, cookie: cookie)
    cookie   = response['Set-Cookie'] if response['Set-Cookie']

    response.body.wont_equal ""
    old_session_id = response.body

    response = response_for(app: renewer, cookie: cookie)
    cookie   = response['Set-Cookie'] if response['Set-Cookie']
    response = response_for(app: only_session_id, cookie: cookie)

    response.body.wont_equal ""
    response.body.wont_equal old_session_id
  end

  it "destroys session" do
    response = response_for(app: incrementor)
    response = response_for(app: only_session_id, cookie: response)

    response.body.wont_equal ""
    old_session_id = response.body

    response = response_for(app: destroy_session, cookie: response)
    response = response_for(app: only_session_id, cookie: response)

    response.body.wont_equal ""
    response.body.wont_equal old_session_id
  end

  it "survives broken cookies" do
    response = response_for(
      app: incrementor,
      cookie: "rack.session=blarghfasel"
    )
    response.body.must_equal ({"counter"=>1}.to_s)

    response = response_for(
      app: [incrementor, { secrets: @secret }],
      cookie: "rack.session="
    )
    response.body.must_equal ({"counter"=>1}.to_s)
  end

  it "barks on too big cookies" do
    lambda{
      response_for(app: bigcookie, request: { fatal: true })
    }.must_raise Rack::MockRequest::FatalWarning
  end

  it "loads from a cookie with encryption" do
    app = [incrementor, { secrets: @secret }]

    response = response_for(app: app)
    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>2}.to_s)

    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>3}.to_s)

    app = [incrementor, { secrets: random_encryptor_secret }]

    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>1}.to_s)
  end

  it "loads from a cookie with accept-only integrity hash for graceful key rotation" do
    response = response_for(app: [incrementor, { secrets: @secret }])

    new_secret = random_encryptor_secret

    app = [incrementor, { secrets: [new_secret, @secret] }]
    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>2}.to_s)

    newer_secret = random_encryptor_secret

    app = [incrementor, { secrets: [newer_secret, new_secret] }]
    response = response_for(app: app, cookie: response)

    response.body.must_equal ({"counter"=>3}.to_s)
  end

  it 'loads from a legacy hmac cookie' do
    legacy_session = Rack::Session::Cookie::Base64::Marshal.new.encode({ 'counter' => 1, 'session_id' => 'abcdef' })
    legacy_secret  = 'test legacy secret'
    legacy_digest  = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, legacy_secret, legacy_session)

    legacy_cookie = "rack.session=#{legacy_session}--#{legacy_digest}; path=/; HttpOnly"

    app = [incrementor, { secrets: @secret, legacy_hmac_secret: legacy_secret }]
    response = response_for(app: app, cookie: legacy_cookie)
    response.body.must_equal ({"counter"=>2}.to_s)
  end

  it "ignores tampered session cookies" do
    app = [incrementor, { secrets: @secret }]

    response = response_for(app: app)
    response.body.must_equal ({"counter"=>1}.to_s)

    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>2}.to_s)

    encoded_cookie = response["Set-Cookie"].split('=', 2).last.split(';').first
    decoded_cookie = Base64.urlsafe_decode64(Rack::Utils.unescape(encoded_cookie))

    tampered_cookie = "rack.session=#{Base64.urlsafe_encode64(decoded_cookie.tap { |m|
      m[m.size - 1] = (m[m.size - 1].unpack('C')[0] ^ 1).chr
    })}"

    response = response_for(app: app, cookie: tampered_cookie)
    response.body.must_equal ({"counter"=>1}.to_s)
  end

  it 'rejects a forged plain Base64::Marshal cookie when secrets: is configured' do
    # Construct a forged cookie without knowing the secret: plain Base64-encoded
    # Marshal payload, identical to what an attacker would send.
    forged_payload = { 'session_id' => 'attacker-fixed', 'counter' => 999 }
    forged_cookie = "rack.session=#{Base64.strict_encode64(Marshal.dump(forged_payload))}"

    app = [incrementor, { secrets: @secret }]

    # The forged cookie must be rejected; session starts fresh (counter = 1).
    response = response_for(app: app, cookie: forged_cookie)
    response.body.must_equal ({"counter" => 1}.to_s)
  end

  it 'rejects a forged plain Base64::Marshal cookie when secrets: and serialize_json: true are configured' do
    # serialize_json: true only affects the encryptor serializer; the coder
    # fallback must also be suppressed when encryptors are configured.
    forged_payload = { 'session_id' => 'attacker-fixed', 'counter' => 999 }
    forged_cookie = "rack.session=#{Base64.strict_encode64(Marshal.dump(forged_payload))}"

    app = [incrementor, { secrets: @secret, serialize_json: true }]

    response = response_for(app: app, cookie: forged_cookie)
    response.body.must_equal ({"counter" => 1}.to_s)
  end

  it 'rejects session cookie with different purpose' do
    app = [incrementor, { secrets: @secrets }]
    other_app = [incrementor, { secrets: @secrets, key: 'other' }]

    response = response_for(app: app)
    response.body.must_equal ({"counter"=>1}.to_s)

    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>2}.to_s)

    response = response_for(app: other_app, cookie: response)
    response.body.must_equal ({"counter"=>1}.to_s)
  end

  it 'adds to RACK_ERRORS on encryptor errors' do
    echo_rack_errors = lambda do |env|
      env["rack.session"]["counter"] ||= 0
      env["rack.session"]["counter"] += 1
      Rack::Response.new(env[Rack::RACK_ERRORS].flush.tap(&:rewind).read).to_a
    end

    app = [incrementor, { secrets: @secret }]
    err_app = [echo_rack_errors, { secrets: @secret }]

    response = response_for(app: app)
    response.body.must_equal ({"counter"=>1}.to_s)

    encoded_cookie = response["Set-Cookie"].split('=', 2).last.split(';').first
    decoded_cookie = Base64.urlsafe_decode64(Rack::Utils.unescape(encoded_cookie))

    tampered_cookie = "rack.session=#{Base64.urlsafe_encode64(decoded_cookie.tap { |m|
      m[m.size - 1] = "\0"
    })}"

    response = response_for(app: err_app, cookie: tampered_cookie)
    response.body.must_equal "Session cookie encryptor error: invalid message\n"
  end

  it 'ignores tampered with legacy hmac cookie' do
    legacy_session = Rack::Session::Cookie::Base64::Marshal.new.encode({ 'counter' => 1, 'session_id' => 'abcdef' })
    legacy_secret  = 'test legacy secret'
    legacy_digest  = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, legacy_secret, legacy_session).reverse

    legacy_cookie = "rack.session=#{legacy_session}--#{legacy_digest}; path=/; HttpOnly"

    app = [incrementor, { secret: @secret, legacy_hmac_secret: legacy_secret }]
    response = response_for(app: app, cookie: legacy_cookie)
    response.body.must_equal ({"counter"=>1}.to_s)
  end

  it "supports custom digest instance for legacy hmac cookie" do
    legacy_hmac    = 'SHA256'
    legacy_session = Rack::Session::Cookie::Base64::Marshal.new.encode({ 'counter' => 1, 'session_id' => 'abcdef' })
    legacy_secret  = 'test legacy secret'
    legacy_digest  = OpenSSL::HMAC.hexdigest(legacy_hmac, legacy_secret, legacy_session)
    legacy_cookie = "rack.session=#{legacy_session}--#{legacy_digest}; path=/; HttpOnly"

    app = [incrementor, {
      secrets: @secret, legacy_hmac_secret: legacy_secret, legacy_hmac: legacy_hmac
    }]

    response = response_for(app: app, cookie: legacy_cookie)
    response.body.must_equal ({"counter"=>2}.to_s)

    response = response_for(app: app, cookie: response)
    response.body.must_equal ({"counter"=>3}.to_s)
  end

  it "can handle Rack::Lint middleware" do
    response = response_for(app: incrementor)

    lint = Rack::Lint.new(session_id)
    response = response_for(app: lint, cookie: response)
    response.body.wont_be :nil?
  end

  it "can handle middleware that inspects the env" do
    class TestEnvInspector
      def initialize(app)
        @app = app
      end
      def call(env)
        env.inspect
        @app.call(env)
      end
    end

    response = response_for(app: incrementor)

    inspector = TestEnvInspector.new(session_id)
    response = response_for(app: inspector, cookie: response)
    response.body.wont_be :nil?
  end

  it "returns the session id in the session hash" do
    response = response_for(app: incrementor)
    response.body.must_equal ({"counter"=>1}.to_s)

    response = response_for(app: session_id, cookie: response)
    response.body.must_match(/"session_id"\s*=>/)
    response.body.must_match(/"counter"\s*=>\s*1/)
  end

  it "does not return a cookie if set to secure but not using ssl" do
    app = [incrementor, { secure: true }]

    response = response_for(app: app)
    response["Set-Cookie"].must_be_nil

    response = response_for(app: app, request: { "HTTPS" => "on" })
    response["Set-Cookie"].wont_be :nil?
    response["Set-Cookie"].must_match(/secure/)
  end

  it "does not return a cookie if cookie was not read/written" do
    response = response_for(app: nothing)
    response["Set-Cookie"].must_be_nil
  end

  it "does not return a cookie if cookie was not written (only read)" do
    response = response_for(app: session_id)
    response["Set-Cookie"].must_be_nil
  end

  it "returns even if not read/written if :expire_after is set" do
    app = [nothing, { expire_after: 3600 }]
    request = { "rack.session" => { "not" => "empty" } }
    response = response_for(app: app, request: request)
    response["Set-Cookie"].wont_be :nil?
  end

  it "returns no cookie if no data was written and no session was created previously, even if :expire_after is set" do
    app = [nothing, { expire_after: 3600 }]
    response = response_for(app: app)
    response["Set-Cookie"].must_be_nil
  end

  it "exposes :secrets in env['rack.session.option']" do
    response = response_for(app: [session_option[:secrets], { secrets: @secret }])
    response.body.must_equal @secret.inspect
  end

  it "exposes :coder in env['rack.session.option']" do
    response = response_for(app: session_option[:coder])
    response.body.must_match(/Base64::Marshal/)
  end

  it 'exposes correct :coder when a secrets is used' do
    response = response_for(app: session_option[:coder], secrets: @secret)
    response.body.must_match(/Marshal/)
  end

  it "allows passing in a hash with session data from middleware in front" do
    request = { 'rack.session' => { foo: 'bar' } }
    response = response_for(app: session_id, request: request)
    response.body.must_match(/foo/)
  end

  it "allows modifying session data with session data from middleware in front" do
    request = { 'rack.session' => { foo: 'bar' } }
    response = response_for(app: incrementor, request: request)
    response.body.must_match(/counter/)
    response.body.must_match(/foo/)
  end

  it "allows more than one '--' in the cookie when calculating legacy digests" do
    @counter = 0
    app = lambda do |env|
      env["rack.session"]["message"] ||= ""
      env["rack.session"]["message"] += "#{(@counter += 1).to_s}--"
      hash = env["rack.session"].dup
      hash.delete("session_id")
      Rack::Response.new(hash["message"]).to_a
    end

    # another example of an unsafe coder is Base64.urlsafe_encode64
    unsafe_coder = Class.new {
      def encode(hash); hash.inspect end
      def decode(str); eval(str) if str; end
    }.new

    legacy_session = unsafe_coder.encode('message' => "#{@counter += 1}--#{@counter += 1}--", 'session_id' => 'abcdef')
    legacy_secret  = 'test legacy secret'
    legacy_digest  = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, legacy_secret, legacy_session)
    legacy_cookie = "rack.session=#{Rack::Utils.escape legacy_session}--#{legacy_digest}; path=/; HttpOnly"

    _app = [ app, {
      secrets: @secret,
      legacy_hmac_secret: legacy_secret,
      legacy_hmac_coder: unsafe_coder
    }]

    response = response_for(app: _app, cookie: legacy_cookie)
    response.body.must_equal "1--2--3--"
  end

  it 'allows for non-strict encoded cookie' do
    long_session_app = lambda do |env|
      env['rack.session']['value'] = 'A' * 256
      env['rack.session']['counter'] = 1
      hash = env["rack.session"].dup
      hash.delete("session_id")
      Rack::Response.new(hash.inspect).to_a
    end

    non_strict_coder = Class.new {
      def encode(str)
        [Marshal.dump(str)].pack('m')
      end

      def decode(str)
        return unless str

        Marshal.load(str.unpack('m').first)
      end
    }.new

    non_strict_response = response_for(app: [
      long_session_app, { coder: non_strict_coder }
    ])

    response = response_for(app: [
      incrementor
    ], cookie: non_strict_response)

    response.body.must_match /"value"\s*=>\s*"#{'A' * 256}"/
    response.body.must_match /"counter"\s*=>\s*2/
    response.body.must_match(/\A{[^}]+}\z/)
  end

  describe 'audience binding' do
    def audience_incrementor
      @audience_incrementor ||= lambda do |env|
      env["rack.session"]["counter"] ||= 0
      env["rack.session"]["counter"] += 1
      hash = env["rack.session"].dup
      hash.delete("session_id")
      Rack::Response.new(hash.inspect).to_a
      end
    end

    def mounted_app(secret, extra = {})
      Rack::URLMap.new(
        '/app-a' => Rack::Session::Cookie.new(
          audience_incrementor, { secrets: secret, audience: '/app-a' }.merge(extra)
        ),
        '/app-b' => Rack::Session::Cookie.new(
          audience_incrementor, { secrets: secret, audience: '/app-b' }.merge(extra)
        )
      )
    end

    def get_from(app, path, cookie = nil)
      env = cookie ? { 'HTTP_COOKIE' => cookie } : {}
      Rack::MockRequest.new(app).get("#{path}/", env)
    end

    def cookie_value(response)
      response["Set-Cookie"].split('=', 2).last.split(';').first
    end

    def old_format_cookie(secret)
      response = response_for(app: [audience_incrementor, { secrets: secret }])
      Rack::Utils.unescape(cookie_value(response))
    end

    it 'rejects a cookie replayed from one audience into another' do
      app = mounted_app(@secret)

      response_a = get_from(app, '/app-a')
      response_a.body.must_equal({ "counter" => 1 }.to_s)

      # The cookie minted for /app-a must not establish a session on /app-b.
      response_b = get_from(app, '/app-b', response_a["Set-Cookie"])
      response_b.body.must_equal({ "counter" => 1 }.to_s)

      # ... while still being valid for /app-a.
      response_a2 = get_from(app, '/app-a', response_a["Set-Cookie"])
      response_a2.body.must_equal({ "counter" => 2 }.to_s)
    end

    it 'accepts an old format cookie only inside the migration window and reissues it' do
      old_value = old_format_cookie(@secret)

      app = mounted_app(@secret, accept_legacy_cookies_until: 3600)

      response = get_from(app, '/app-a', "rack.session=#{old_value}")
      response.body.must_equal({ "counter" => 2 }.to_s)

      new_value = Rack::Utils.unescape(cookie_value(response))
      new_value.wont_equal old_value

      # The reissued cookie is audience-bound: it decrypts for /app-a only.
      app_a_encryptor = Rack::Session::Encryptor.new(
        @secret, purpose: 'rack.session', audience: '/app-a'
      )
      app_b_encryptor = Rack::Session::Encryptor.new(
        @secret, purpose: 'rack.session', audience: '/app-b'
      )
      old_encryptor = Rack::Session::Encryptor.new(
        @secret, purpose: 'rack.session'
      )

      app_a_encryptor.decrypt(new_value)["counter"].must_equal 2
      -> { app_b_encryptor.decrypt(new_value) }.must_raise(
        Rack::Session::Encryptor::Error
      )
      -> { old_encryptor.decrypt(new_value) }.must_raise(
        Rack::Session::Encryptor::Error
      )

      # Subsequent requests use the new audience-bound cookie directly.
      follow_up = get_from(app, '/app-a', "rack.session=#{new_value}")
      follow_up.body.must_equal({ "counter" => 3 }.to_s)
    end

    it 'migrates a read-only old session even when the app does not write it' do
      old_value = old_format_cookie(@secret)
      app = mounted_app(@secret, accept_legacy_cookies_until: 3600)

      reader = Rack::URLMap.new(
        '/app-a' => Rack::Session::Cookie.new(
          only_session_id,
          secrets: @secret,
          audience: '/app-a',
          accept_legacy_cookies_until: 3600
        )
      )

      response = get_from(reader, '/app-a', "rack.session=#{old_value}")
      response["Set-Cookie"].wont_be_nil

      new_value = Rack::Utils.unescape(cookie_value(response))
      app_a_encryptor = Rack::Session::Encryptor.new(
        @secret, purpose: 'rack.session', audience: '/app-a'
      )
      app_a_encryptor.decrypt(new_value).wont_be_nil
    end

    it 'rejects an old format cookie when the migration window has expired' do
      old_value = old_format_cookie(@secret)

      app = mounted_app(@secret, accept_legacy_cookies_until: Time.now - 60)
      response = get_from(app, '/app-a', "rack.session=#{old_value}")
      response.body.must_equal({ "counter" => 1 }.to_s)
    end

    it 'rejects an old format cookie without an explicit migration window' do
      old_value = old_format_cookie(@secret)

      app = mounted_app(@secret)
      response = get_from(app, '/app-a', "rack.session=#{old_value}")
      response.body.must_equal({ "counter" => 1 }.to_s)
    end

    it 'selects the uniquely valid cookie regardless of order' do
      app = mounted_app(@secret)

      response_a1 = get_from(app, '/app-a')
      response_a2 = get_from(app, '/app-a', response_a1["Set-Cookie"])
      response_b = get_from(app, '/app-b')

      value_a = Rack::Utils.unescape(cookie_value(response_a2))
      value_b = Rack::Utils.unescape(cookie_value(response_b))

      [
        "rack.session=#{value_a}; rack.session=#{value_b}",
        "rack.session=#{value_b}; rack.session=#{value_a}"
      ].each do |cookie|
        response = get_from(app, '/app-a', cookie)
        response.body.must_equal({ "counter" => 3 }.to_s)
      end
    end

    it 'rejects two distinct cookies that both validate for this audience' do
      app = mounted_app(@secret)

      response_a1 = get_from(app, '/app-a')
      response_a2 = get_from(app, '/app-a', response_a1["Set-Cookie"])
      response_a3 = get_from(app, '/app-a', response_a2["Set-Cookie"])

      value_2 = Rack::Utils.unescape(cookie_value(response_a2))
      value_3 = Rack::Utils.unescape(cookie_value(response_a3))

      [
        "rack.session=#{value_2}; rack.session=#{value_3}",
        "rack.session=#{value_3}; rack.session=#{value_2}"
      ].each do |cookie|
        response = get_from(app, '/app-a', cookie)
        response.body.must_equal({ "counter" => 1 }.to_s)
      end
    end

    it 'accepts a duplicated, identical valid cookie' do
      app = mounted_app(@secret)

      response_a1 = get_from(app, '/app-a')
      response_a2 = get_from(app, '/app-a', response_a1["Set-Cookie"])
      value = Rack::Utils.unescape(cookie_value(response_a2))

      cookie = "rack.session=#{value}; rack.session=#{value}"
      response = get_from(app, '/app-a', cookie)
      response.body.must_equal({ "counter" => 3 }.to_s)
    end

    it 'rejects two distinct legacy cookies during the migration window' do
      old_value_1 = old_format_cookie(@secret)

      other = response_for(app: [audience_incrementor, { secrets: @secret }])
      old_value_2 = Rack::Utils.unescape(cookie_value(other))

      app = mounted_app(@secret, accept_legacy_cookies_until: 3600)

      [
        "rack.session=#{old_value_1}; rack.session=#{old_value_2}",
        "rack.session=#{old_value_2}; rack.session=#{old_value_1}"
      ].each do |cookie|
        response = get_from(app, '/app-a', cookie)
        response.body.must_equal({ "counter" => 1 }.to_s)
      end
    end

    it 'binds audiences in v1 encryption mode too' do
      app = Rack::URLMap.new(
        '/app-a' => Rack::Session::Cookie.new(
          audience_incrementor,
          secrets: @secret, audience: '/app-a', mode: :v1
        ),
        '/app-b' => Rack::Session::Cookie.new(
          audience_incrementor,
          secrets: @secret, audience: '/app-b', mode: :v1
        )
      )

      response_a = get_from(app, '/app-a')
      response_a.body.must_equal({ "counter" => 1 }.to_s)

      response_b = get_from(app, '/app-b', response_a["Set-Cookie"])
      response_b.body.must_equal({ "counter" => 1 }.to_s)

      response_a2 = get_from(app, '/app-a', response_a["Set-Cookie"])
      response_a2.body.must_equal({ "counter" => 2 }.to_s)
    end

    it 'only accepts legacy HMAC cookies inside the migration window' do
      legacy_secret = 'test legacy secret'
      legacy_session =
        Rack::Session::Cookie::Base64::Marshal.new.encode(
          { 'counter' => 1, 'session_id' => 'abcdef' }
        )
      legacy_digest = OpenSSL::HMAC.hexdigest('SHA1', legacy_secret, legacy_session)
      legacy_cookie = "rack.session=#{legacy_session}--#{legacy_digest}"

      options = {
        secrets: @secret,
        audience: '/app-a',
        legacy_hmac_secret: legacy_secret
      }

      # No explicit migration window: rejected.
      app = Rack::Session::Cookie.new(audience_incrementor, options)
      response = Rack::MockRequest.new(app).get(
        '/', 'HTTP_COOKIE' => legacy_cookie
      )
      response.body.must_equal({ "counter" => 1 }.to_s)

      # Expired window: rejected.
      app = Rack::Session::Cookie.new(
        audience_incrementor,
        options.merge(accept_legacy_cookies_until: Time.now - 60)
      )
      response = Rack::MockRequest.new(app).get(
        '/', 'HTTP_COOKIE' => legacy_cookie
      )
      response.body.must_equal({ "counter" => 1 }.to_s)

      # Open window: accepted and reissued as a new format cookie.
      app = Rack::Session::Cookie.new(
        audience_incrementor,
        options.merge(accept_legacy_cookies_until: 3600)
      )
      response = Rack::MockRequest.new(app).get(
        '/', 'HTTP_COOKIE' => legacy_cookie
      )
      response.body.must_equal({ "counter" => 2 }.to_s)
      response["Set-Cookie"].wont_be_nil

      new_value = Rack::Utils.unescape(cookie_value(response))
      app_a_encryptor = Rack::Session::Encryptor.new(
        @secret, purpose: 'rack.session', audience: '/app-a'
      )
      app_a_encryptor.decrypt(new_value)["counter"].must_equal 2
    end

    it 'requires :audience to be a String' do
      -> do
        Rack::Session::Cookie.new(
          audience_incrementor, secrets: @secret, audience: :app_a
        )
      end.must_raise ArgumentError
    end
  end
end
