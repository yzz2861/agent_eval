# frozen_string_literal: true

RSpec.describe Dry::Container::ReadOnlyView do
  subject(:view) { container.read_only_view(keys: allowed_keys, namespaces: allowed_namespaces) }

  let(:container) { Dry::Container.new }
  let(:allowed_keys) { [] }
  let(:allowed_namespaces) { [] }

  before do
    container.register("public.item", "public value")
    container.register("public.nested.item", "nested public value")
    container.register("public_other", "lookalike value")
    container.register("secret.token", "signing key")
  end

  describe "explicit keys" do
    let(:allowed_keys) { "public.item" }

    it "resolves only the configured full key" do
      expect(view.resolve("public.item")).to eq("public value")
      expect(view.resolve(:"public.item")).to eq("public value")
      expect(view["public.item"]).to eq("public value")
      expect(view.key?("public.item")).to be(true)
    end

    it "does not expose nested, lookalike, or secret keys" do
      expect(view.keys).to eq(["public.item"])
      expect(view.each_key.to_a).to eq(["public.item"])
      expect(view.to_a).to eq([["public.item", "public value"]])

      aggregate_failures do
        %w[public.nested.item public_other secret.token].each do |key|
          expect(view.key?(key)).to be(false)
        end
      end
    end

    it "does not expose mutation methods or the source container" do
      expect(view).not_to respond_to(:register)
      expect(view).not_to respond_to(:merge)
      expect(view).not_to respond_to(:decorate)
      expect(view).not_to respond_to(:namespace)
      expect(view).not_to respond_to(:container)
    end

    it "uses identical errors for unauthorized existing and absent keys" do
      existing_error = resolve_error("secret.token")
      absent_error = resolve_error("secret.absent")

      expect(existing_error.class).to eq(absent_error.class)
      expect(existing_error.message).to eq(absent_error.message.gsub("absent", "token"))
      expect(existing_error.message).not_to include("signing key")
      expect(existing_error.receiver).to be(view)
    end

    it "limits KeyError suggestions to visible keys" do
      allowed = container.read_only_view(namespaces: "public")

      begin
        allowed.resolve("public.iem")
      rescue KeyError => error
        expect(error.spell_checker.corrections).to include('"public.item"')
        expect(error.spell_checker.corrections).not_to include('"secret.token"')
      end
    end

    it "does not call a fallback block for an unauthorized key" do
      called = false

      expect { view.resolve("secret.token") { called = true } }.to raise_error(KeyError)
      expect(called).to be(false)
    end

    it "calls a fallback block for an authorized but missing key" do
      allowed = container.read_only_view(keys: "public.absent")

      expect(allowed.resolve("public.absent") { :fallback }).to be(:fallback)
    end
  end

  describe "namespaces" do
    let(:allowed_namespaces) { "public" }

    it "resolves descendants of the namespace" do
      expect(view.resolve("public.item")).to eq("public value")
      expect(view.resolve("public.nested.item")).to eq("nested public value")
      expect(view["public.nested.item"]).to eq("nested public value")
    end

    it "lists and iterates only descendants of the namespace" do
      expect(view.keys).to match_array(%w[public.item public.nested.item])
      expect(view.each_key.to_a).to match_array(%w[public.item public.nested.item])
      expect(view.to_h).to eq(
        "public.item" => "public value",
        "public.nested.item" => "nested public value"
      )
    end

    it "respects the namespace separator" do
      expect(view.key?("public_other")).to be(false)
      expect { view.resolve("public_other") }.to raise_error(KeyError)
    end

    it "does not grant access outside the namespace" do
      expect(view.key?("secret.token")).to be(false)
      expect { view.resolve("secret.token") }.to raise_error(KeyError)
    end

    it "accepts a trailing namespace separator at creation" do
      trailing_view = container.read_only_view(namespaces: "public.")

      expect(trailing_view.keys).to match_array(%w[public.item public.nested.item])
    end

    it "uses the configured namespace separator" do
      custom_container = Class.new do
        extend Dry::Container::Mixin
      end
      custom_container.config.namespace_separator = "-"
      custom_container.register("public-item", "public value")
      custom_container.register("public_other", "lookalike value")
      custom_view = custom_container.read_only_view(namespaces: "public")

      expect(custom_view.keys).to eq(["public-item"])
      expect(custom_view.key?("public_other")).to be(false)
    end
  end

  describe "construction" do
    it "accepts symbol and array allowlists" do
      allowed = container.read_only_view(
        keys: [:"public.item"],
        namespaces: [:"public.nested"]
      )

      expect(allowed.keys).to match_array(%w[public.item public.nested.item])
      expect(allowed.allowed).to eq(
        keys: ["public.item"],
        namespaces: ["public.nested"]
      )
    end

    it "accepts singular key and namespace arguments" do
      by_key = container.read_only_view(key: "public.item")
      by_namespace = container.read_only_view(namespace: "public")

      expect(by_key.keys).to eq(["public.item"])
      expect(by_namespace.keys).to match_array(%w[public.item public.nested.item])
    end

    it "requires an explicit allowlist" do
      expect { container.read_only_view }.to raise_error(
        ArgumentError,
        "at least one key or namespace must be given"
      )
    end

    it "freezes its visibility rules" do
      allowed = container.read_only_view(keys: "public.item")

      expect(allowed).to be_frozen
      expect { allowed.allowed[:keys] << "secret.token" }.to raise_error(FrozenError)
    end

    it "does not allow namespaces without a non-empty separator" do
      custom_container = Class.new do
        extend Dry::Container::Mixin
      end
      custom_container.config.namespace_separator = ""

      expect { custom_container.read_only_view(namespaces: "public") }.to raise_error(
        ArgumentError,
        "a non-empty namespace separator is required for namespaces"
      )
    end

    it "exposes the class through the resolver-oriented alias" do
      expect(Dry::Container::ResolverView).to be(described_class)
      expect(Dry::Container::View).to be(described_class)
      expect(container.resolver_view(keys: "public.item")).to be_a(described_class)
      expect(container.view(keys: "public.item")).to be_a(described_class)
    end
  end

  describe "dynamic containers" do
    it "applies the fixed allowlist to keys registered after creation" do
      allowed = container.read_only_view(namespaces: "public")
      container.register("public.added", "added value")
      container.register("secret.added", "added secret")

      expect(allowed.resolve("public.added")).to eq("added value")
      expect(allowed.key?("secret.added")).to be(false)
      expect(allowed.keys).to include("public.added")
      expect(allowed.keys).not_to include("secret.added")
    end
  end

  describe "custom resolvers" do
    it "normalizes a resolver KeyError without revealing source keys" do
      resolver = Class.new do
        def call(container, key)
          raise Dry::Container::KeyError.new(
            "source suggested secret.token for #{key}",
            key: key.to_s,
            receiver: container
          )
        end

        def key?(container, key)
          container.key?(key.to_s)
        end

        def keys(container)
          container.keys
        end
      end.new
      custom_container = Class.new(Dry::Container).new
      custom_container.config.resolver = resolver
      custom_container.register("public.item", "public value")
      custom_container.register("secret.token", "secret value")
      allowed = custom_container.read_only_view(keys: "public.item")

      expect { allowed.resolve("public.item") }.to raise_error(KeyError) do |error|
        expect(error.message).to eq('key not found: "public.item"')
        expect(error.message).not_to include("secret.token")
        expect(error.receiver).to be(allowed)
      end
    end
  end

  describe "factory security boundary" do
    it "does not contain an accessible factory that captures the source container" do
      container.register("public.escape", -> { container.resolve("secret.token") })
      allowed = container.read_only_view(keys: "public.escape")

      expect(allowed.resolve("public.escape")).to eq("signing key")
    end
  end

  def resolve_error(key)
    view.resolve(key)
  rescue KeyError => error
    error
  end
end
