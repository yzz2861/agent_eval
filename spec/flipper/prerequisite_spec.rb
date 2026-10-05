RSpec.describe Flipper::Feature, 'prerequisites' do
  let(:flipper) { Flipper.new(Flipper::Adapters::Memory.new, memoize: false) }
  let(:actor) { Flipper::Actor.new('User;1', 'allow_payments' => true) }
  let(:other_actor) { Flipper::Actor.new('User;2', 'allow_payments' => false) }

  it 'enables a gated settlement flow only when its payment prerequisite is on' do
    Flipper.register(:staff) { |check_actor| check_actor.flipper_id == actor.flipper_id }
    flipper.enable_prerequisite(:new_checkout, :basic_payments)
    flipper.enable_group(:new_checkout, :staff)

    expect(flipper[:new_checkout].enabled?(actor)).to be(false)

    flipper.enable(:basic_payments)
    expect(flipper[:new_checkout].enabled?(actor)).to be(true)

    flipper.disable(:basic_payments)
    expect(flipper[:new_checkout].enabled?(actor)).to be(false)
  end

  it 'requires an enabled ordinary gate in addition to prerequisites' do
    flipper.enable_prerequisite(:new_checkout, :basic_payments)
    flipper.enable(:basic_payments)

    expect(flipper[:new_checkout].enabled?(actor)).to be(false)
  end

  it 'supports prerequisites that must be off' do
    flipper.enable(:new_checkout)
    flipper.enable_prerequisite(:new_checkout, :legacy_checkout, false)

    expect(flipper[:new_checkout].enabled?).to be(true)

    flipper.enable(:legacy_checkout)
    expect(flipper[:new_checkout].enabled?).to be(false)
  end

  it 'treats a missing dependency as not satisfying an on prerequisite' do
    flipper.enable(:new_checkout)
    flipper.enable_prerequisite(:new_checkout, :basic_payments)

    expect(flipper[:new_checkout].enabled?).to be(false)
    expect(flipper.exist?(:basic_payments)).to be(false)
  end

  it 'treats a missing dependency as satisfying an off prerequisite' do
    flipper.enable(:new_checkout)
    flipper.enable_prerequisite(:new_checkout, :legacy_checkout, false)

    expect(flipper[:new_checkout].enabled?).to be(true)
  end

  it 'reports the feature chain for an indirect cycle' do
    flipper.enable(:new_checkout)
    flipper.enable(:payments)
    flipper.enable(:risk)
    flipper.enable_prerequisite(:new_checkout, :payments)
    flipper.enable_prerequisite(:payments, :risk)
    flipper.enable_prerequisite(:risk, :new_checkout)

    expect do
      flipper[:new_checkout].enabled?
    end.to raise_error(Flipper::CircularDependency) do |error|
      expect(error.chain).to eq(%w(new_checkout payments risk new_checkout))
    end
  end

  it 'evaluates a shared dependency once for one request and uses the same actor and context' do
    checks = []
    Flipper.register(:payment_rollout) do |check_actor, context|
      checks << [check_actor, context.feature_name, context.actors]
      check_actor.flipper_properties['allow_payments']
    end

    flipper.enable(:new_checkout)
    flipper.enable(:card_payments)
    flipper.enable(:wallet_payments)
    flipper.enable_prerequisite(:new_checkout, :card_payments)
    flipper.enable_prerequisite(:new_checkout, :wallet_payments)
    flipper.enable_prerequisite(:card_payments, :payments)
    flipper.enable_prerequisite(:wallet_payments, :payments)
    flipper.enable_group(:payments, :payment_rollout)

    expect(flipper[:new_checkout].enabled?(actor)).to be(true)
    expect(checks.size).to eq(1)
    expect(checks.first[0].flipper_id).to eq(actor.flipper_id)
    expect(checks.first[1]).to eq('payments')
    expect(checks.first[2].map(&:flipper_id)).to eq([actor.flipper_id])

    actor.flipper_properties['allow_payments'] = false
    expect(flipper[:new_checkout].enabled?(actor)).to be(false)
    expect(checks.size).to eq(2)
  end

  it 'uses the same actor and context for dependent gates without sharing that result across requests' do
    checks = []
    Flipper.register(:payment_rollout) do |check_actor, context|
      checks << [check_actor.flipper_id, context.feature_name.to_s, context.actors.map(&:flipper_id)]
      true
    end

    Flipper.instance = flipper
    flipper.enable(:new_checkout)
    flipper.enable_prerequisite(:new_checkout, :basic_payments)
    flipper.enable_group(:basic_payments, :payment_rollout)

    expect(flipper[:new_checkout].enabled?(actor)).to be(true)
    payment_checks = checks.select { |check| check[1] == 'basic_payments' }
    expect(payment_checks.map(&:first)).to eq([actor.flipper_id])
    expect(payment_checks.map(&:last)).to eq([[actor.flipper_id]])

    expect(flipper[:new_checkout].enabled?(other_actor)).to be(true)
    payment_checks = checks.select { |check| check[1] == 'basic_payments' }
    expect(payment_checks.map(&:first)).to eq([actor.flipper_id, other_actor.flipper_id])
  end

  it 'does not include the prerequisite gate among ordinary enabled gates' do
    flipper.enable_group(:new_checkout, :staff)
    flipper.enable_prerequisite(:new_checkout, :basic_payments)

    expect(flipper[:new_checkout].enabled_gate_names).to eq([:group])
  end

end
