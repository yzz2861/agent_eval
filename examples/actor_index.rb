require 'bundler/setup'
require 'flipper'

# Optional actor allowlist index: a version-bound Bloom filter sits in front
# of the precise actor list so features with huge allowlists do not need to
# pull the entire set for every enabled? check.
#
# Memory vs. false positive rate (see Flipper::BloomFilter docs):
#   p = 0.01   -> ~9.6 bits per actor, 7 hashes  (~1.2 MB per 1M actors)
#   p = 0.001  -> ~14.4 bits per actor, 10 hashes (~1.8 MB per 1M actors)
index = Flipper::ActorIndexes::Bloom.new(capacity: 100_000, false_positive_rate: 0.01)
checker = Flipper::ActorIndex.new(index)

search = Flipper::Feature.new(:search, Flipper::Adapters::Memory.new, actor_index: checker)

user = Flipper::Actor.new('User;1')
outsider = Flipper::Actor.new('User;999999')

search.enable(user) # also syncs the index

puts "Search for user:     #{search.enabled?(user)}"
puts "Search for outsider: #{search.enabled?(outsider)}"

# The outsider was excluded by the Bloom filter alone, no precise query ran.
puts "Precise queries:   #{checker.precise_queries}"
puts "Bloom exclusions:  #{checker.bloom_exclusions}"
puts "Fallbacks (stale): #{checker.fallbacks}"

# A Bloom "maybe" never enables the feature by itself: possible hits are
# always confirmed against the precise list, and when the index version lags
# the list version every check falls back to a precise query.
