# frozen_string_literal: true

# Released under the MIT License.

require_relative 'helper'

require 'rack/response'
require 'rack/mock'
require 'rack/utils'
require 'rack/lint'

require_relative '../lib/rack/session/pool'
require_relative '../lib/rack/session/cookie'

describe Rack::Session::Pool do
  session_key = Rack::Session::Pool::DEFAULT_OPTIONS[:key]
  session_match = /#{session_key}=([0-9a-fA-F]+);/

  def counter_app
    Rack::Lint.new(lambda do |env|
      session = env["rack.session"]
      if env["PATH_INFO"] == "/write"
        session["counter"] = (session["counter"] || 0) + 1
        session.commit! if env["QUERY_STRING"] == "commit"
      end
      Rack::Response.new(session["counter"].inspect).to_a
    end)
  end

  describe "manual commit mode" do
    it "does not persist uncommitted changes" do
      pool = Rack::Session::Pool.new(counter_app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      res1 = req.get("/write")
      res1.body.must_equal "1"
      res1["Set-Cookie"].must_be_nil

      # The pool only holds the empty, uncommitted session:
      pool.pool.values.must_equal [{}]

      # A second request starts from scratch, nothing was persisted:
      res2 = req.get("/write")
      res2.body.must_equal "1"
      res2["Set-Cookie"].must_be_nil
      pool.pool.values.must_equal [{}, {}]
    end

    it "persists the session only when committed" do
      pool = Rack::Session::Pool.new(counter_app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      res1 = req.get("/write?commit")
      res1.body.must_equal "1"
      cookie = res1["Set-Cookie"]
      cookie.must_match(session_match)

      # Uncommitted change is visible locally but not persisted:
      res2 = req.get("/write", "HTTP_COOKIE" => cookie)
      res2.body.must_equal "2"
      res2["Set-Cookie"].must_be_nil

      # The stored session still holds the committed value:
      res3 = req.get("/", "HTTP_COOKIE" => cookie)
      res3.body.must_equal "1"

      # Committing again updates the stored session:
      req.get("/write?commit", "HTTP_COOKIE" => cookie)
      res4 = req.get("/", "HTTP_COOKIE" => cookie)
      res4.body.must_equal "2"
    end

    it "isolates nested hashes and arrays from the stored session" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["profile"] = {"name" => "alice", "tags" => ["a"]}
          session.commit!
        when "/mutate"
          session["profile"]["name"] = "mallory"
          session["profile"]["tags"] << "b"
          session.commit! if env["QUERY_STRING"] == "commit"
        end
        Rack::Response.new(session["profile"].inspect).to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/seed")["Set-Cookie"]

      # Mutating nested structures without committing must not leak into
      # the stored session:
      res = req.get("/mutate", "HTTP_COOKIE" => cookie)
      res.body.must_equal({"name" => "mallory", "tags" => ["a", "b"]}.inspect)
      pool.pool.values.must_equal [{"profile" => {"name" => "alice", "tags" => ["a"]}}]

      res = req.get("/", "HTTP_COOKIE" => cookie)
      res.body.must_equal({"name" => "alice", "tags" => ["a"]}.inspect)

      # Committing persists a snapshot of the nested structures:
      req.get("/mutate?commit", "HTTP_COOKIE" => cookie)
      pool.pool.values.must_equal [{"profile" => {"name" => "mallory", "tags" => ["a", "b"]}}]

      # Further nested edits do not leak into the committed snapshot:
      req.get("/mutate", "HTTP_COOKIE" => cookie)
      pool.pool.values.must_equal [{"profile" => {"name" => "mallory", "tags" => ["a", "b"]}}]
    end

    it "does not persist modifications made after a commit" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        if env["PATH_INFO"] == "/write"
          session["counter"] = (session["counter"] || 0) + 1
          session.commit!
          session["counter"] = 99
        end
        Rack::Response.new(session["counter"].inspect).to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      res1 = req.get("/write")
      res1.body.must_equal "99"
      cookie = res1["Set-Cookie"]

      # Only the value at commit time was persisted:
      pool.pool.values.must_equal [{"counter" => 1}]

      res2 = req.get("/", "HTTP_COOKIE" => cookie)
      res2.body.must_equal "1"
    end

    it "only persists key deletion when committed" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["a"] = 1
          session["b"] = 2
          session.commit!
        when "/delete"
          session.delete("a")
          session.commit! if env["QUERY_STRING"] == "commit"
        end
        Rack::Response.new("OK").to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/seed")["Set-Cookie"]

      req.get("/delete", "HTTP_COOKIE" => cookie)
      pool.pool.values.must_equal [{"a" => 1, "b" => 2}]

      req.get("/delete?commit", "HTTP_COOKIE" => cookie)
      pool.pool.values.must_equal [{"b" => 2}]
    end

    it "stages destroy until the session is committed" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["user"] = "alice"
          session.commit!
        when "/destroy"
          session.destroy
          session.commit! if env["QUERY_STRING"] == "commit"
        end
        Rack::Response.new("OK").to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/seed")["Set-Cookie"]
      sid = pool.pool.keys.first

      # Uncommitted destroy leaves the stored session untouched:
      req.get("/destroy", "HTTP_COOKIE" => cookie)
      pool.pool[sid].must_equal({"user" => "alice"})

      # Committed destroy removes the old session and starts a fresh,
      # empty one referenced by a new session id:
      res = req.get("/destroy?commit", "HTTP_COOKIE" => cookie)
      pool.pool.keys.wont_include sid
      pool.pool.size.must_equal 1
      pool.pool.values.must_equal [{}]
      res["Set-Cookie"][session_match, 1].wont_equal cookie[session_match, 1]
    end

    it "renews the session id on commit with :renew" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["user"] = "alice"
          session.commit!
        when "/renew"
          env["rack.session.options"][:renew] = true
          session.commit!
        end
        Rack::Response.new("OK").to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/seed")["Set-Cookie"]
      old_sid = pool.pool.keys.first

      res = req.get("/renew", "HTTP_COOKIE" => cookie)
      new_cookie = res["Set-Cookie"]
      new_cookie.wont_be_nil
      new_cookie[session_match, 1].wont_equal cookie[session_match, 1]

      # The data was migrated to the new session id:
      pool.pool.keys.wont_include old_sid
      pool.pool.size.must_equal 1
      pool.pool.values.must_equal [{"user" => "alice"}]
    end

    it "drops the session on commit with :drop" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["user"] = "alice"
          session.commit!
        when "/drop"
          env["rack.session.options"][:drop] = true
          session.commit!
        end
        Rack::Response.new("OK").to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/seed")["Set-Cookie"]
      pool.pool.size.must_equal 1

      res = req.get("/drop", "HTTP_COOKIE" => cookie)
      pool.pool.must_be_empty
      res["Set-Cookie"].must_be_nil
    end

    it "commits an empty session" do
      app = Rack::Lint.new(lambda do |env|
        env["rack.session"].commit!
        Rack::Response.new(env["rack.session"].to_hash.inspect).to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      res = req.get("/")
      res.body.must_equal "{}"
      res["Set-Cookie"].must_match(session_match)
      pool.pool.values.must_equal [{}]
    end

    it "reports storage failures to the application before the response" do
      pool = nil
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        session["user"] = "alice"
        # Simulate the stored session disappearing underneath the request,
        # e.g. due to concurrent expiry:
        pool.pool.clear
        committed = session.commit!
        Rack::Response.new(committed.inspect).to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      res = req.get("/")
      res.body.must_equal "false"
      res["Set-Cookie"].must_be_nil
      pool.pool.must_be_empty
    end

    it "leaves the stored session untouched when the request raises" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["user"] = "alice"
          session["profile"] = {"tags" => ["a"]}
          session.commit!
        when "/boom"
          session["user"] = "mallory"
          session["profile"]["tags"] << "b"
          raise "boom"
        end
        Rack::Response.new("OK").to_a
      end)
      pool = Rack::Session::Pool.new(app, commit_mode: :manual)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/seed")["Set-Cookie"]

      lambda { req.get("/boom", "HTTP_COOKIE" => cookie) }.must_raise RuntimeError
      pool.pool.values.must_equal [{"user" => "alice", "profile" => {"tags" => ["a"]}}]
    end

    it "can be enabled per request via session options" do
      app = Rack::Lint.new(lambda do |env|
        env["rack.session.options"][:commit_mode] = :manual
        env["rack.session"]["counter"] = (env["rack.session"]["counter"] || 0) + 1
        Rack::Response.new(env["rack.session"]["counter"].to_s).to_a
      end)
      pool = Rack::Session::Pool.new(app)
      req = Rack::MockRequest.new(pool)

      res1 = req.get("/")
      res1.body.must_equal "1"
      res1["Set-Cookie"].must_be_nil

      res2 = req.get("/")
      res2.body.must_equal "1"
    end

    it "keeps the default auto save behavior" do
      app = Rack::Lint.new(lambda do |env|
        env["rack.session"]["counter"] = (env["rack.session"]["counter"] || 0) + 1
        Rack::Response.new(env["rack.session"]["counter"].to_s).to_a
      end)
      pool = Rack::Session::Pool.new(app)
      req = Rack::MockRequest.new(pool)

      cookie = req.get("/")["Set-Cookie"]
      cookie.must_match(session_match)

      res = req.get("/", "HTTP_COOKIE" => cookie)
      res.body.must_equal "2"
    end
  end
end

describe Rack::Session::Cookie do
  secret = "manual-commit-boundary-secret" * 3

  describe "manual commit mode" do
    it "leaves the client cookie untouched unless the session is committed" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        case env["PATH_INFO"]
        when "/seed"
          session["user"] = "alice"
          session["profile"] = {"roles" => ["user"]}
          session.commit!
        when "/mutate"
          session["user"] = "mallory"
          session["profile"]["roles"] << "admin"
        end
        body = "#{session['user']}:#{session['profile']['roles'].join(',')}"
        Rack::Response.new(body).to_a
      end)
      store = Rack::Session::Cookie.new(app, secrets: secret, commit_mode: :manual)
      req = Rack::MockRequest.new(store)

      # First request commits the session and receives a cookie:
      res1 = req.get("/seed")
      res1.body.must_equal "alice:user"
      cookie = res1["Set-Cookie"]
      cookie.wont_be_nil

      # Second request mutates the session, including nested structures,
      # but never commits: no cookie is sent back, so the client keeps
      # the original one:
      res2 = req.get("/mutate", "HTTP_COOKIE" => cookie)
      res2.body.must_equal "mallory:user,admin"
      res2["Set-Cookie"].must_be_nil

      # The original cookie still yields the committed values:
      res3 = req.get("/", "HTTP_COOKIE" => cookie)
      res3.body.must_equal "alice:user"
    end

    it "persists the snapshot taken at commit time" do
      app = Rack::Lint.new(lambda do |env|
        session = env["rack.session"]
        if env["PATH_INFO"] == "/write"
          session["user"] = "bob"
          session.commit!
          # Changes after commit! are not part of the committed snapshot:
          session["user"] = "carol"
        end
        Rack::Response.new(session["user"].inspect).to_a
      end)
      store = Rack::Session::Cookie.new(app, secrets: secret, commit_mode: :manual)
      req = Rack::MockRequest.new(store)

      res1 = req.get("/write")
      res1.body.must_equal '"carol"'
      cookie = res1["Set-Cookie"]
      cookie.wont_be_nil

      # A second request with the new cookie sees the committed snapshot:
      res2 = req.get("/", "HTTP_COOKIE" => cookie)
      res2.body.must_equal '"bob"'
    end
  end
end
