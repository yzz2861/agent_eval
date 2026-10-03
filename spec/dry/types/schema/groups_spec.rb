# frozen_string_literal: true

RSpec.describe Dry::Types::Schema, "key groups" do
  def schema
    Dry::Types["nominal.hash"].schema(
      username?: "nominal.string",
      password?: "nominal.string",
      token?: "nominal.string"
    )
  end

  let(:connection) do
    schema.all_or_none(:username, :password)
          .exactly_one(:token, [:username, :password])
  end

  let(:strict_connection) do
    Dry::Types["nominal.hash"].schema(
      username?: "strict.string",
      password?: "strict.string",
      token?: "strict.string"
    ).all_or_none(:username, :password)
     .exactly_one(:token, [:username, :password])
  end

  describe "definition" do
    it "raises early when a top-level path does not exist" do
      expect { schema.at_least_one(:username, :nope) }.to raise_error(
        ArgumentError, /\[:nope\] is not a key of the schema/
      )
    end

    it "raises early when a nested path goes through a non-schema key" do
      expect { schema.exactly_one([[:username, :nope]]) }.to raise_error(
        ArgumentError, /\[:username\] is not a nested schema/
      )
    end

    it "raises early when a nested key does not exist" do
      nested = Dry::Types["nominal.hash"].schema(
        creds: Dry::Types["nominal.hash"].schema(token?: "nominal.string")
      )

      expect { nested.exactly_one([[:creds, :nope]]) }.to raise_error(
        ArgumentError, /\[:creds, :nope\] is not a key of the schema/
      )
    end

    it "exposes the defined groups" do
      expect(connection.key_groups.map(&:kind)).to eql(%i[all_or_none exactly_one])
    end

    it "returns a new schema, leaving the original untouched" do
      extended = connection.at_least_one(:token)

      expect(extended.key_groups.size).to be(3)
      expect(connection.key_groups.size).to be(2)
    end

    it "rejects an invalid check moment" do
      expect { connection.at_least_one(:token, check: :whenever) }.to raise_error(
        ArgumentError, /unknown check moment :whenever/
      )
    end
  end

  describe "exactly_one" do
    subject(:type) { schema.exactly_one(:username, :token) }

    it "accepts input with exactly one member present" do
      expect(type.(username: "jane")).to eql(username: "jane")
      expect(type.(token: "abc")).to eql(token: "abc")
    end

    it "rejects input with no members present" do
      expect { type.({}) }.to raise_error(
        Dry::Types::KeyGroupError,
        /expected exactly one of \["username", "token"\] to be present, got \[\]/
      )
    end

    it "rejects input with several members present" do
      expect { type.(username: "jane", token: "abc") }.to raise_error(
        Dry::Types::KeyGroupError,
        /expected exactly one .* got \["username", "token"\]/
      )
    end

    it "treats an explicit nil as present" do
      expect(type.(token: nil)).to eql(token: nil)
    end

    it "supports bundled members" do
      expect(connection.(token: "abc")).to eql(token: "abc")
      expect(connection.(username: "jane", password: "secret")).to eql(
        username: "jane", password: "secret"
      )

      expect { connection.(token: "abc", username: "jane") }.to raise_error(
        Dry::Types::KeyGroupError,
        /expected all or none of \["username", "password"\]/
      )
    end
  end

  describe "at_least_one" do
    subject(:type) { schema.at_least_one(:username, :token) }

    it "accepts one or more members" do
      expect(type.(username: "jane")).to eql(username: "jane")
      expect(type.(username: "jane", token: "abc")).to eql(username: "jane", token: "abc")
    end

    it "rejects input with no members" do
      expect { type.({}) }.to raise_error(
        Dry::Types::KeyGroupError,
        /expected at least one of \["username", "token"\] to be present, got none/
      )
    end
  end

  describe "all_or_none" do
    subject(:type) { schema.all_or_none(:username, :password) }

    it "accepts all members missing" do
      expect(type.({})).to eql({})
    end

    it "accepts all members present" do
      expect(type.(username: "jane", password: "secret")).to eql(
        username: "jane", password: "secret"
      )
    end

    it "rejects a partial group" do
      expect { type.(username: "jane") }.to raise_error(
        Dry::Types::KeyGroupError,
        /expected all or none .* missing \["password"\]/
      )
    end

    it "accepts explicitly nil values as present" do
      expect(type.(username: nil, password: nil)).to eql(username: nil, password: nil)
    end
  end

  describe "check moment" do
    context "before defaults" do
      subject(:type) do
        Dry::Types["nominal.hash"].schema(
          username?: Dry::Types["nominal.string"].default("admin"),
          token?: "nominal.string"
        ).at_least_one(:username, :token)
      end

      it "does not count default values" do
        expect { type.({}) }.to raise_error(Dry::Types::KeyGroupError, /got none/)
      end
    end

    context "after defaults" do
      subject(:type) do
        Dry::Types["nominal.hash"].schema(
          username?: Dry::Types["nominal.string"].default("admin"),
          token?: "nominal.string"
        ).at_least_one(:username, :token, check: :after_defaults)
      end

      it "counts default values" do
        expect(type.({})).to eql(username: "admin")
      end

      it "is skipped when defaults are not resolved" do
        expect { type.apply({}, resolve_defaults: false) }.to raise_error(
          Dry::Types::KeyGroupError, /got none/
        )
      end
    end
  end

  describe "error reporting" do
    subject(:type) { strict_connection }

    it "keeps member type errors alongside group errors" do
      exception = begin
        type.call(token: 123, username: "jane", password: "secret")
      rescue Dry::Types::MultipleError => e
        e
      end

      expect(exception).to be_a(Dry::Types::MultipleError)
      expect(exception.errors).to include(an_instance_of(Dry::Types::SchemaError))
      expect(exception.errors).to include(an_instance_of(Dry::Types::KeyGroupError))
    end

    it "raises the single group error directly" do
      expect { type.({}) }.to raise_error(Dry::Types::KeyGroupError)
    end

    it "preserves the absence of group checks for schemas without groups" do
      strict = Dry::Types["nominal.hash"].schema(username: "strict.string")
      expect { strict.call(username: 123) }.to raise_error(Dry::Types::SchemaError)
    end
  end

  describe "#try" do
    subject(:type) { strict_connection }

    it "reports group errors without losing per-key results" do
      result = type.try(token: 123, username: "jane", password: "secret")

      expect(result).to be_failure
      expect(result.error.meta[:token].success?).to be(false)
      expect(result.error.group_errors).to include(
        an_object_having_attributes(kind: :exactly_one)
      )
    end

    it "succeeds for conforming input" do
      expect(type.try(token: "abc")).to be_success
    end

    it "yields the failure when a block is given" do
      expect { |probe| type.try({}, &probe) }.to yield_with_args(
        an_instance_of(Dry::Types::Result::Failure)
      )
    end

    it "does not invoke constructors a second time" do
      calls = []
      counting = Dry::Types["nominal.string"].constructor(-> value {
        calls << value
        value.to_s
      })
      type = Dry::Types["nominal.hash"].schema(
        a?: counting, b?: "nominal.string"
      ).exactly_one(:a, :b)

      begin
        type.try(a: :x)
      rescue Dry::Types::CoercionError
        # expected: :b is missing? no - b is omittable; exactly_one satisfied by :a
      end

      expect(calls).to eql([:x])
    end
  end

  describe "safe call" do
    subject(:type) { connection }

    it "falls back on a group violation" do
      expect(type.call({}) { |output| [:fallback, output] }.first).to be(:fallback)
    end

    it "returns the coerced hash on success" do
      expect(type.call(token: "abc") { :fallback }).to eql(token: "abc")
    end
  end

  describe "nested fixed paths" do
    subject(:type) do
      creds = Dry::Types["nominal.hash"].schema(
        token?: "nominal.string",
        username?: "nominal.string",
        password?: "nominal.string"
      )

      Dry::Types["nominal.hash"].schema(creds?: creds).exactly_one(
        [[:creds, :token]], [[:creds, :username], [:creds, :password]]
      )
    end

    it "accepts one nested member" do
      expect(type.(creds: {token: "abc"})).to eql(creds: {token: "abc"})
    end

    it "rejects several nested members" do
      expect { type.(creds: {token: "abc", username: "jane", password: "secret"}) }.to raise_error(
      Dry::Types::KeyGroupError,
      /expected exactly one of \["creds\.token", "\(creds\.username \+ creds\.password\)"\]/
    )
    end

    it "treats a missing intermediate hash as absent" do
      expect { type.({}) }.to raise_error(Dry::Types::KeyGroupError, /got \[\]/)
    end

    it "keeps enforcing the nested schema's own rules" do
      nested_type = Dry::Types["nominal.hash"].schema(
        token: "nominal.string"
      )
      type = Dry::Types["nominal.hash"].schema(creds: nested_type)

      expect { type.(creds: {}) }.to raise_error(
        Dry::Types::SchemaError, /invalid type for :creds.*:token is missing/m
      )
    end
  end

  describe "AST" do
    subject(:type) { connection }

    it "survives an AST round trip" do
      restored = Dry::Types::Compiler.new(Dry::Types).call(type.to_ast)

      expect(restored).to eql(type)
    end

    it "keeps enforcing groups after compilation" do
      restored = Dry::Types::Compiler.new(Dry::Types).call(type.to_ast)

      expect { restored.({}) }.to raise_error(Dry::Types::KeyGroupError)
      expect(restored.(token: "abc")).to eql(token: "abc")
    end

    it "includes the check moment in the AST" do
      type = schema.at_least_one(:token, check: :after_defaults)
      groups = type.to_ast[1][1][:key_groups]

      expect(groups).to include(
        hash_including(kind: :at_least_one, check: :after_defaults)
      )
    end

    it "round-trips through json and params hash ASTs" do
      %w[json.hash params.hash].each do |name|
        type = Dry::Types[name].schema(a?: "nominal.string").at_least_one(:a)
        restored = Dry::Types::Compiler.new(Dry::Types).call(type.to_ast)

        expect(restored).to eql(type)
      end
    end
  end

  describe "schema composition" do
    it "preserves groups when extending a schema" do
      extended = connection.schema(age?: "nominal.integer")

      expect(extended.key_groups).to eql(connection.key_groups)
    end

    it "preserves groups when merging schemas" do
      merged = connection.merge(schema)

      expect(merged.key_groups).to eql(connection.key_groups)
    end

    it "drops groups when clearing keys" do
      expect(connection.clear.key_groups).to be_empty
    end

    it "works through constructor wrappers" do
      wrapped = connection.constructor(&:to_h)

      expect(wrapped.(token: "abc")).to eql(token: "abc")
      expect { wrapped.({}) }.to raise_error(Dry::Types::KeyGroupError)
    end

    it "is not enforced by lax schemas" do
      expect(connection.lax.({})).to eql({})
    end
  end

  describe "#to_s" do
    it "prints the groups" do
      expect(connection.to_s).to include(
        "groups={all_or_none(username | password) " \
        "exactly_one(token | (username + password))}"
      )
    end
  end
end
