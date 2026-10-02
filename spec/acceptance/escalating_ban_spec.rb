# frozen_string_literal: true

require_relative "../spec_helper"
require_relative "../support/manual_clock"

describe "escalating ban" do
  include Rack::Test::Methods

  before do
    $clock = ManualClock.new
    $store = Rack::Attack::BanMemoryStore.new(clock: $clock)
    $ban = Rack::Attack::EscalatingBan.new(
      levels: [
        { name: "minute", maxretry: 2, bantime: 60 },
        { name: "five",   maxretry: 4, bantime: 300 }
      ],
      decay: 900,
      store: $store,
      clock: $clock
    )

    Rack::Attack.blocklist("escalating") do |request|
      $ban.filter(request.ip, request.env["HTTP_X_EVENT_ID"]) do
        request.path.include?("private-place")
      end
    end
  end

  def app
    Rack::Builder.new do
      use Rack::Attack
      run ->(_env) { [200, {}, ["Hello World"]] }
    end.to_app
  end

  def violation(event_id)
    get "/private-place", {}, "REMOTE_ADDR" => "1.2.3.4", "HTTP_X_EVENT_ID" => event_id
  end

  it "does not block clean traffic below the threshold" do
    violation("e1")
    assert_equal 403, last_response.status

    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    assert_equal 200, last_response.status
  end

  it "escalates from a one minute ban to a five minute ban" do
    violation("e1")
    violation("e2")

    status = $ban.status("1.2.3.4")
    assert status.banned?
    assert_equal "minute", status.level.name
    assert_equal $clock.now + 60, status.banned_until

    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    assert_equal 403, last_response.status

    # Re-offenses push the discriminator onto the next level.
    violation("e3")
    violation("e4")

    status = $ban.status("1.2.3.4")
    assert_equal "five", status.level.name
    assert_equal $clock.now + 300, status.banned_until
  end

  it "renews the ban for offenses repeated while banned" do
    violation("e1")
    violation("e2")
    first_until = $clock.now + 60

    $clock.advance(50)
    violation("e3")

    status = $ban.status("1.2.3.4")
    assert_equal "minute", status.level.name
    assert_equal $clock.now + 60, status.banned_until
    assert_operator status.banned_until, :>, first_until
  end

  it "never upgrades twice for the same event id" do
    violation("dup")
    3.times { violation("dup") }

    status = $ban.status("1.2.3.4")
    assert_equal 1, status.violations
    refute status.banned?

    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    assert_equal 200, last_response.status
  end

  it "expires the ban and decays violations over time" do
    violation("a")
    violation("b")
    # First ban runs for a minute; re-offending inside it escalates.
    $clock.advance(600)
    violation("c")
    violation("d")
    assert_equal "five", $ban.status("1.2.3.4").level.name
    five_until = $clock.now + 300

    # Still banned a moment before the five minute ban ends.
    $clock.advance(299)
    assert_equal five_until, $ban.status("1.2.3.4").banned_until
    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    assert_equal 403, last_response.status

    # The ban ends; only the two recent violations are still remembered.
    $clock.advance(1)
    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    assert_equal 200, last_response.status
    status = $ban.status("1.2.3.4")
    refute status.banned?
    assert_equal 2, status.violations

    # After the decay window the discriminator starts over at the bottom.
    $clock.advance(900)
    status = $ban.status("1.2.3.4")
    assert_equal 0, status.violations
    assert_nil status.level
  end

  it "keeps the longest ongoing ban even after older violations decay" do
    ban = Rack::Attack::EscalatingBan.new(
      levels: [
        { name: "short", maxretry: 2, bantime: 60 },
        { name: "long",  maxretry: 4, bantime: 300 }
      ],
      decay: 100,
      store: $store,
      clock: $clock
    )
    %w[a b c d].each { |event_id| ban.report("1.2.3.4", event_id) }
    long_until = $clock.now + 300

    $clock.advance(101)
    status = ban.report("1.2.3.4", "late")

    assert status.banned?
    assert_equal "long", status.level.name
    assert_equal long_until, status.banned_until
  end
end
