require 'flipper'

RSpec.describe 'Flipper layer integration' do
  let(:actors) do
    (1..20).map { |number| Flipper::Actor.new("User;#{number}") }
  end

  let(:initial_layers) do
    Flipper::Layers.new(
      experiments: {
        checkout: 0...400,
        search: 400...800,
      },
      onboarding: {
        onboarding_a: 800...1000,
      }
    )
  end

  let(:adapter) { Flipper::Adapters::Memory.new }
  subject(:flipper) { Flipper.new(adapter, layers: initial_layers) }

  before do
    flipper.enable_percentage_of_actors(:checkout, 100)
    flipper.enable_percentage_of_actors(:search, 100)
    flipper.enable_percentage_of_actors(:onboarding_a, 100)
  end

  it 'allocates fixed, mutually exclusive actor buckets within a layer' do
    results = actors.each_with_object(Hash.new { |hash, actor| hash[actor] = [] }) do |actor, enabled|
      enabled[actor] << :checkout if flipper.enabled?(:checkout, actor)
      enabled[actor] << :search if flipper.enabled?(:search, actor)
    end

    expect(results.select { |_, features| features.include?(:checkout) }.keys.map(&:flipper_id)).to contain_exactly(
      'User;4', 'User;6', 'User;8', 'User;9', 'User;14', 'User;18'
    )
    expect(results.select { |_, features| features.include?(:search) }.keys.map(&:flipper_id)).to contain_exactly(
      'User;1', 'User;3', 'User;10', 'User;12', 'User;13', 'User;15', 'User;16', 'User;19', 'User;20'
    )
    expect(results.values).to all(have_attributes(size: be <= 1))
  end

  it 'uses independent layer domains for different layers' do
    actor = Flipper::Actor.new('User;1')

    expect(initial_layers.layers[:experiments].bucket_for(actor)).not_to eq(
      initial_layers.layers[:onboarding].bucket_for(actor)
    )
    expect(flipper.enabled?(:search, actor)).to be(true)
    expect(flipper.enabled?(:onboarding_a, actor)).to be(true)

    other_actor = Flipper::Actor.new('User;9')
    expect(flipper.enabled?(:checkout, other_actor)).to be(true)
    expect(flipper.enabled?(:onboarding_a, other_actor)).to be(false)
  end

  it 'continues to the feature percentage gate using its separate hash domain' do
    flipper.enable_percentage_of_actors(:search, 50)

    expect(flipper.enabled?(:search, Flipper::Actor.new('User;10'))).to be(true)
    expect(flipper.enabled?(:search, Flipper::Actor.new('User;1'))).to be(false)
  end

  it 'does not reassign another feature when an experiment is disabled' do
    search_actor = Flipper::Actor.new('User;1')
    expect(flipper.enabled?(:search, search_actor)).to be(true)

    flipper.disable(:checkout)

    expect(flipper.enabled?(:checkout, Flipper::Actor.new('User;9'))).to be(false)
    expect(flipper.enabled?(:search, search_actor)).to be(true)
  end

  it 'does not reshuffle other allocations when a stopped experiment is removed from configuration' do
    before_search = actors.select { |actor| flipper.enabled?(:search, actor) }
    before_checkout = actors.select { |actor| flipper.enabled?(:checkout, actor) }
    flipper.disable(:checkout)

    reduced_layers = Flipper::Layers.new(
      experiments: { search: 400...800 },
      onboarding: { onboarding_a: 800...1000 }
    )
    reconfigured = Flipper.new(adapter, layers: reduced_layers)

    after_search = actors.select { |actor| reconfigured.enabled?(:search, actor) }
    expect(after_search).to eq(before_search)
    expect(actors.map { |actor| reconfigured.enabled?(:checkout, actor) }).to all(be(false))
    expect(before_checkout).not_to be_empty
  end

  it 'limits a changed allocation to its own feature and leaves other layers unchanged' do
    search_actor = Flipper::Actor.new('User;1')
    onboarding_actor = Flipper::Actor.new('User;1')
    expect(flipper.enabled?(:search, search_actor)).to be(true)
    expect(flipper.enabled?(:onboarding_a, onboarding_actor)).to be(true)

    changed_layers = Flipper::Layers.new(
      experiments: {
        checkout: 0...400,
        search: 650...800,
      },
      onboarding: {
        onboarding_a: 800...1000,
      }
    )
    reconfigured = Flipper.new(adapter, layers: changed_layers)

    expect(reconfigured.enabled?(:search, search_actor)).to be(false)
    expect(reconfigured.enabled?(:search, Flipper::Actor.new('User;19'))).to be(true)
    expect(reconfigured.enabled?(:checkout, Flipper::Actor.new('User;9'))).to be(true)
    expect(reconfigured.enabled?(:onboarding_a, onboarding_actor)).to be(true)
  end
end
