# frozen_string_literal: true

RSpec.describe Dry::System::Provider::Plan do
  FakeProvider = Struct.new(:name, :depends_on, keyword_init: true)

  let(:providers_hash) { {} }

  let(:resolver) do
    hash = providers_hash
    ->(name) { hash[name] }
  end

  def build_plan(*roots)
    described_class.build(roots, resolver)
  end

  before do
    providers_hash[:a] = FakeProvider.new(name: :a, depends_on: [])
    providers_hash[:b] = FakeProvider.new(name: :b, depends_on: [:a])
    providers_hash[:c] = FakeProvider.new(name: :c, depends_on: [:b])
  end

  it "orders dependencies before dependents and reverses for stopping" do
    plan = build_plan(:c)

    expect(plan.start_order).to eq %i[a b c]
    expect(plan.stop_order).to eq %i[c b a]
  end

  it "includes transitive dependencies in names" do
    expect(build_plan(:c).names).to eq %i[a b c]
  end

  it "handles diamond dependencies without duplicates" do
    providers_hash[:d] = FakeProvider.new(name: :d, depends_on: [:b, :c])

    expect(build_plan(:d).start_order).to eq %i[a b c d]
  end

  it "raises ProviderNotFoundError when a root provider is missing" do
    expect { build_plan(:zzz) }.to raise_error(
      Dry::System::ProviderNotFoundError, /:zzz/
    )
  end

  it "raises ProviderDependencyNotFoundError when a dependency is missing" do
    providers_hash[:b] = FakeProvider.new(name: :b, depends_on: [:ghost])

    expect { build_plan(:b) }.to raise_error(
      Dry::System::ProviderDependencyNotFoundError, /:ghost/
    )
  end

  it "raises ProviderDependencyCycleError on direct cycles" do
    providers_hash[:a] = FakeProvider.new(name: :a, depends_on: [:b])
    providers_hash[:b] = FakeProvider.new(name: :b, depends_on: [:a])

    expect { build_plan(:a) }.to raise_error(
      Dry::System::ProviderDependencyCycleError, /a -> b -> a/
    )
  end

  it "raises ProviderDependencyCycleError on self cycles" do
    providers_hash[:a] = FakeProvider.new(name: :a, depends_on: [:a])

    expect { build_plan(:a) }.to raise_error(
      Dry::System::ProviderDependencyCycleError, /a -> a/
    )
  end

  it "does not invoke side effects while building the plan" do
    build_plan(:c)

    expect(resolver.call(:c)).to be_a(FakeProvider)
  end
end
