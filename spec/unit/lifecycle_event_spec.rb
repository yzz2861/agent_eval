# frozen_string_literal: true

RSpec.describe Dry::System::LifecycleEvent do
  let(:error) { RuntimeError.new("boom") }

  it "exposes its fields and status predicates" do
    event = described_class.new(action: :start, provider: :db, status: :run)

    expect(event.action).to eq :start
    expect(event.provider).to eq :db
    expect(event.status).to eq :run
    expect(event.error).to be_nil
    expect(event).to be_run
    expect(event).not_to be_skipped
    expect(event).not_to be_failed
  end

  it "reports failed events and renders a readable string" do
    event = described_class.new(
      action: :stop, provider: :db, status: :failed, error: error
    )

    expect(event).to be_failed
    expect(event.error).to equal(error)
    expect(event.to_s).to include "[failed] stop db"
    expect(event.to_s).to include "boom"
  end

  it "renders container-wide events without a provider name" do
    event = described_class.new(action: :shutdown, status: :run)

    expect(event.provider).to be_nil
    expect(event.to_s).to eq "[run] shutdown"
  end
end
