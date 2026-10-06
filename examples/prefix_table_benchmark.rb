# frozen_string_literal: true

require "benchmark"
require "ipaddr"

SEED = 0x4d595df4d0f33173
RULES_PER_FAMILY = 200
QUERIES_PER_FAMILY = 500

rng = Random.new(SEED)
table = IPAddr::PrefixTable.new
naive_rules = []

def random_prefix(rng, family, length)
  size = family == Socket::AF_INET ? 2**32 : 2**128
  IPAddr.new(rng.rand(size), family).mask(length)
end

def naive_lookup(rules, address)
  rules
    .select { |prefix,| prefix.include?(address) }
    .max_by do |prefix, _, priority, sequence|
      [prefix.prefix, priority, -sequence]
    end
end

table.add("0.0.0.0/0", :v4_default)
table.add("::/0", :v6_default)
naive_rules << [IPAddr.new("0.0.0.0/0"), :v4_default, 0, 0]
naive_rules << [IPAddr.new("::/0"), :v6_default, 0, 1]

RULES_PER_FAMILY.times do |index|
  prefix = random_prefix(rng, Socket::AF_INET, 8 + rng.rand(25))
  id = "v4-#{index}".to_sym
  priority = rng.rand(4)
  table.add(prefix.cidr, id, index, priority: priority)
  naive_rules << [prefix, id, priority, table.size - 1]
end

RULES_PER_FAMILY.times do |index|
  prefix = random_prefix(rng, Socket::AF_INET6, 16 + rng.rand(113))
  id = "v6-#{index}".to_sym
  priority = rng.rand(4)
  table.add(prefix.cidr, id, index, priority: priority)
  naive_rules << [prefix, id, priority, table.size - 1]
end

queries = Array.new(QUERIES_PER_FAMILY) do
  IPAddr.new(rng.rand(2**32), Socket::AF_INET)
end + Array.new(QUERIES_PER_FAMILY) do
  IPAddr.new(rng.rand(2**128), Socket::AF_INET6)
end

visited_nodes = 0
benchmark = Benchmark.bm(16) do |x|
  x.report("naive scan") do
    queries.each { |address| naive_lookup(naive_rules, address) }
  end

  x.report("prefix trie") do
    queries.each do |address|
      visited_nodes += table.lookup(address).visited_nodes
    end
  end
end

rule_checks = queries.size * naive_rules.size
puts
puts "rules: #{naive_rules.size}"
puts "queries: #{queries.size}"
puts "naive rule checks: #{rule_checks}"
puts "trie nodes visited: #{visited_nodes}"
puts "average trie nodes/query: #{format("%.2f", visited_nodes / queries.size.to_f)}"
puts "trie time/naive time: #{format("%.3f", benchmark.last.real / benchmark.first.real)}"
