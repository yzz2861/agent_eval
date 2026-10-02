# frozen_string_literal: true

# Demonstration of Rack::Attack::EscalatingBan with an injected clock and
# the thread-safe in-memory store. Run with:
#
#   bundle exec ruby examples/escalating_ban.rb

require_relative "../lib/rack/attack"

clock = Class.new {
  attr_reader :now
  def initialize = (@now = 0)
  def call = @now
  def advance(seconds) = @now += seconds
}.new

store = Rack::Attack::BanMemoryStore.new(clock: clock)
ban = Rack::Attack::EscalatingBan.new(
  levels: [
    { name: "1 minute", maxretry: 2, bantime: 60 },
    { name: "5 minutes", maxretry: 4, bantime: 300 }
  ],
  decay: 900,
  store: store,
  clock: clock
)

discriminator = "1.2.3.4"

def show(clock, ban, discriminator, note)
  status = ban.status(discriminator)
  level = status.banned? ? status.level.name : "-"
  puts "t=#{clock.call.to_s.rjust(4)}s  #{note.ljust(34)} violations=#{status.violations}  banned=#{status.banned?}  level=#{level}"
end

ban.report(discriminator, "evt-1")
show(clock, ban, discriminator, "first violation")

ban.report(discriminator, "evt-2")
show(clock, ban, discriminator, "threshold crossed -> 1 min")

ban.report(discriminator, "evt-2") # same event id: ignored
show(clock, ban, discriminator, "duplicate event id re-reported")

clock.advance(50)
ban.report(discriminator, "evt-3")
show(clock, ban, discriminator, "re-offense renews the 1 min ban")

clock.advance(20)
ban.report(discriminator, "evt-4")
show(clock, ban, discriminator, "next threshold -> 5 min")

clock.advance(299)
show(clock, ban, discriminator, "still banned near the end")

clock.advance(2)
show(clock, ban, discriminator, "ban expired; recent violations kept")

clock.advance(600)
show(clock, ban, discriminator, "older violations decay")

clock.advance(300)
show(clock, ban, discriminator, "fully restored to the bottom")
