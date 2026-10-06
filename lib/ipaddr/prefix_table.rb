# frozen_string_literal: true

require 'ipaddr'

class IPAddr
  # PrefixTable is an updatable longest-prefix-match table built on top
  # of IPAddr's parsing.  It keeps one binary trie per address family
  # (IPv4 and IPv6 stay fully independent, including their default
  # routes), stores caller supplied data on every rule, and resolves
  # ties between rules sharing one prefix through an explicit priority.
  #
  #   table = IPAddr::PrefixTable.new
  #   table.add("0.0.0.0/0", :v4_default)
  #   table.add("10.0.0.0/8", :corp)
  #   id = table.add("10.1.2.0/24", :dmz, priority: 10)
  #   table.lookup("10.1.2.9")      #=> #<Match prefix=10.1.2.0/24 ...>
  #   table.delete(id)              # falls back to the 10.0.0.0/8 rule
  #
  # Lookups never cache: every query walks the trie from the root, so
  # deleting a rule immediately re-exposes the correct ancestor rule.
  # The number of trie nodes touched by the last lookup is available
  # through Match#nodes_visited and PrefixTable#last_nodes_visited.
  class PrefixTable
    # A single declared rule.  +id+ is the stable identity returned by
    # #add, +prefix+ the normalized (masked) IPAddr, +priority+ the
    # explicit priority inside its prefix, +seq+ the insertion order
    # used to keep same-priority duplicates deterministic, and +data+
    # whatever the caller attached.
    Rule = Struct.new(:id, :prefix, :priority, :seq, :data) do
      def prefix_length
        prefix.prefix
      end
    end

    # The outcome of a lookup: the winning rule plus how the choice was
    # made.  #prefix and #rule_id are exposed so callers can explain
    # why a request matched.
    Match = Struct.new(:rule, :nodes_visited) do
      def rule_id
        rule.id
      end

      def prefix
        rule.prefix
      end

      def priority
        rule.priority
      end

      def data
        rule.data
      end
    end

    class Node
      attr_accessor :children, :rules

      def initialize
        @children = [nil, nil]
        @rules = [] # sorted by [-priority, seq]
      end
    end

    attr_reader :last_nodes_visited

    def initialize
      @roots = { Socket::AF_INET => Node.new, Socket::AF_INET6 => Node.new }
      @rules = {}
      @next_id = 1
      @next_seq = 0
      @last_nodes_visited = 0
    end

    # Declares a rule for +prefix+ (anything IPAddr.new accepts, or an
    # IPAddr) carrying +data+.  Rules on the same prefix are ordered by
    # +priority+ (higher wins); equal priorities keep declaration order,
    # so repeated declarations are stable.  Returns the rule id.
    def add(prefix, data = nil, priority: 0)
      network = normalize_prefix(prefix)
      rule = Rule.new(@next_id, network, priority, @next_seq, data)
      @next_id += 1
      @next_seq += 1

      node = node_for(network, create: true)
      index = node.rules.index { |existing| existing.priority < priority } || node.rules.size
      node.rules.insert(index, rule)
      @rules[rule.id] = rule
      rule.id
    end

    # Removes the rule previously returned by #add.  Returns the removed
    # Rule, or nil when the id is unknown.  Subsequent lookups fall back
    # to the longest remaining ancestor prefix.
    def delete(rule_id)
      rule = @rules.delete(rule_id)
      return nil unless rule

      node = node_for(rule.prefix, create: false)
      node.rules.delete(rule) if node
      rule
    end

    # Finds the most specific rule covering +address+.  Returns a Match
    # or nil when no prefix (not even the family default route) covers
    # it.  IPv4 addresses only ever consult IPv4 rules and vice versa.
    def lookup(address)
      addr = address.is_a?(IPAddr) ? address : IPAddr.new(address)
      root = @roots[family_of(addr)]
      value = addr.to_i
      width = addr.ipv4? ? 32 : 128

      visits = 0
      best = nil
      node = root
      while node
        visits += 1
        best = node.rules.first unless node.rules.empty?
        break if visits > width
        bit = (value >> (width - visits)) & 1
        node = node.children[bit]
      end

      @last_nodes_visited = visits
      best && Match.new(best, visits)
    end

    # Fetches a declared rule by id, for explaining a Match.
    def rule(rule_id)
      @rules[rule_id]
    end

    def size
      @rules.size
    end

    def empty?
      @rules.empty?
    end

    private

    def family_of(addr)
      addr.ipv4? ? Socket::AF_INET : Socket::AF_INET6
    end

    def normalize_prefix(prefix)
      addr = prefix.is_a?(IPAddr) ? prefix : IPAddr.new(prefix)
      addr.mask(addr.prefix)
    end

    def node_for(network, create:)
      value = network.to_i
      width = network.ipv4? ? 32 : 128
      plen = network.prefix
      node = @roots[family_of(network)]
      plen.times do |depth|
        bit = (value >> (width - 1 - depth)) & 1
        child = node.children[bit]
        if child.nil?
          return nil unless create
          child = node.children[bit] = Node.new
        end
        node = child
      end
      node
    end
  end
end
