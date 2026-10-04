# encoding: utf-8
# frozen_string_literal: true

require 'digest'

module Mail
  # = Thread Index
  #
  # Rebuilds discussion threads from the References and In-Reply-To headers
  # of an incrementally growing collection of messages, e.g. a support
  # mailbox where mail arrives out of order.
  #
  #   index = Mail::ThreadIndex.new
  #   index.add(mail)                 # messages may arrive in any order
  #   index.roots                     #=> ["root-id", ...]
  #   index.children_of("root-id")    #=> ["child-id", ...]
  #   index.unresolved_references     #=> ["missing-ancestor-id", ...]
  #
  # == Placeholders and merging
  #
  # When a message references an ancestor that has not been indexed yet, a
  # placeholder node is kept for the missing Message-ID so the thread stays
  # connected. Once the real message arrives, the placeholder is filled in
  # and its previously collected children are merged into the real node.
  #
  # == Conflicts
  #
  # Two messages that share a Message-ID but have different content are a
  # data integrity problem. The first message wins a slot; every divergent
  # duplicate is reported through #conflicts. Identical duplicates are
  # ignored silently.
  #
  # == Parent selection rules
  #
  # A message can point at several ancestors, so the parent is chosen by
  # the following deterministic rules, in order:
  #
  # 1. The last Message-ID of In-Reply-To wins. It is the explicit
  #    "this is a reply to that" statement of the message itself.
  # 2. Otherwise the last Message-ID of References is used (the nearest
  #    ancestor per RFC 5322).
  # 3. The remaining References entries are only used to link the ancestor
  #    chain (grandparent -> parent). Such inferred links are weak: they
  #    fill gaps but are replaced by the message's own headers once that
  #    message arrives. Among conflicting inferred links the first one
  #    observed wins (only malformed mail produces these).
  # 4. The Subject header is never used: identical subjects do not make
  #    two messages part of the same thread.
  #
  # == Reference cycles
  #
  # Broken or malicious mail can create reference cycles (A replies to B,
  # B replies to A). Cycles are broken deterministically: within each
  # cycle the node with the lexicographically smallest Message-ID drops
  # its parent link and becomes a root. Because the rule only depends on
  # Message-IDs, the resulting forest is identical no matter in which
  # order the messages arrived. All traversals additionally guard with a
  # visited set, so cyclic input can never hang a query.
  class ThreadIndex
    # A divergent duplicate: same Message-ID, different content.
    Conflict = Struct.new(:message_id, :kept_fingerprint, :rejected_fingerprint, :rejected_message)

    # One node per known Message-ID. +message+ is nil while the node is a
    # placeholder for a message that has not arrived yet.
    class Node
      attr_accessor :message, :fingerprint, :parent_id
      attr_reader :message_id, :parent_strength

      def initialize(message_id)
        @message_id = message_id
        @message = nil
        @fingerprint = nil
        @parent_id = nil
        @parent_strength = nil
      end

      def placeholder?
        @message.nil?
      end

      # :direct (own headers) beats :inferred (References of others).
      def assign_parent(parent_id, strength)
        return false if parent_id.nil? || parent_id == message_id
        return false if @parent_strength == :direct
        return false if @parent_strength == :inferred && strength == :inferred
        @parent_id = parent_id
        @parent_strength = strength
        true
      end
    end

    def initialize
      @nodes = {} # message_id => Node, insertion ordered
      @conflicts = []
      @effective_parent = {}
      @dirty = true
    end

    # Adds one Mail::Message to the index. Returns self so calls chain.
    # Raises ArgumentError if the message has no Message-ID.
    def add(message)
      id = self.class.normalize_id(message.message_id)
      raise ArgumentError, 'cannot index a message without a Message-ID' if id.empty?

      reference_ids = extract_message_ids(message, 'References')
      in_reply_to_ids = extract_message_ids(message, 'In-Reply-To')

      (reference_ids + in_reply_to_ids).each { |ref_id| node_for(ref_id) }
      node = node_for(id)

      fingerprint = self.class.fingerprint(message)
      if node.placeholder?
        node.message = message
        node.fingerprint = fingerprint
        direct_parent = in_reply_to_ids.last || reference_ids.last
        node.assign_parent(direct_parent, :direct) if direct_parent
      elsif node.fingerprint != fingerprint
        @conflicts << Conflict.new(id, node.fingerprint, fingerprint, message)
      end

      reference_ids.each_cons(2) do |ancestor_id, descendant_id|
        node_for(descendant_id).assign_parent(ancestor_id, :inferred)
      end

      @dirty = true
      self
    end

    def add_all(messages)
      messages.each { |message| add(message) }
      self
    end

    def include?(message_id)
      @nodes.key?(self.class.normalize_id(message_id))
    end

    def size
      @nodes.size
    end

    # The Mail::Message indexed under this id, or nil for placeholders
    # and unknown ids.
    def message_for(message_id)
      node = @nodes[self.class.normalize_id(message_id)]
      node && node.message
    end

    def placeholder?(message_id)
      node = @nodes[self.class.normalize_id(message_id)]
      !node.nil? && node.placeholder?
    end

    # Message-IDs of nodes without a parent: the roots of the thread
    # forest. Placeholder roots mean the true root has not arrived yet.
    def roots
      recompute_if_dirty
      @nodes.each_key.select { |id| @effective_parent[id].nil? }.sort
    end

    # The parent Message-ID of the given id, or nil for roots and
    # unknown ids.
    def parent_of(message_id)
      recompute_if_dirty
      @effective_parent[self.class.normalize_id(message_id)]
    end

    # Child Message-IDs of the given id, sorted for determinism.
    def children_of(message_id)
      recompute_if_dirty
      id = self.class.normalize_id(message_id)
      @nodes.each_key.select { |other| @effective_parent[other] == id }.sort
    end

    # Message-IDs that were referenced but whose messages have not been
    # indexed yet (the placeholder nodes).
    def unresolved_references
      @nodes.values.select(&:placeholder?).map(&:message_id).sort
    end

    # Divergent duplicates seen so far (same Message-ID, other content).
    def conflicts
      @conflicts.dup
    end

    # The root Message-ID of the thread the given id belongs to.
    # Returns nil for unknown ids.
    def root_of(message_id)
      recompute_if_dirty
      id = self.class.normalize_id(message_id)
      return nil unless @nodes.key?(id)
      seen = {}
      while (parent = @effective_parent[id])
        return id if seen[id] # paranoia guard; cycles are already broken
        seen[id] = true
        id = parent
      end
      id
    end

    # All Message-IDs in the thread hanging under the given id,
    # depth-first and cycle-safe. Unknown ids yield an empty array.
    def thread_ids(message_id)
      recompute_if_dirty
      id = self.class.normalize_id(message_id)
      return [] unless @nodes.key?(id)
      result = []
      stack = [id]
      seen = {}
      until stack.empty?
        current = stack.pop
        next if seen[current]
        seen[current] = true
        result << current
        stack.concat(children_of(current))
      end
      result
    end

    # Strips angle brackets and surrounding whitespace so that ids from
    # different header representations compare equal.
    def self.normalize_id(message_id)
      message_id.to_s.strip.gsub(/\A<+|>+\z/, '').strip
    end

    # Content fingerprint used for duplicate/conflict detection. The
    # Message-ID itself is deliberately excluded.
    def self.fingerprint(message)
      body =
        begin
          message.body.decoded
        rescue StandardError
          message.body.raw_source.to_s
        end
      Digest::SHA256.hexdigest([message.subject.to_s, body].join("\x00"))
    end

    private

    def node_for(id)
      @nodes[id] ||= Node.new(id)
    end

    def extract_message_ids(message, field_name)
      field = message.header[field_name]
      return [] unless field
      Array(field.message_ids).map { |id| self.class.normalize_id(id) }.reject(&:empty?)
    rescue StandardError
      []
    end

    def recompute_if_dirty
      return unless @dirty
      @effective_parent = compute_effective_parents
      @dirty = false
    end

    # Copies the desired parent links and deterministically breaks every
    # cycle by dropping the parent link of the cycle's smallest
    # Message-ID, until a forest remains.
    def compute_effective_parents
      effective = {}
      @nodes.each { |id, node| effective[id] = node.parent_id }
      while (cycle = find_cycle(effective))
        effective[cycle.min] = nil
      end
      effective
    end

    def find_cycle(effective)
      effective.each_key do |start|
        path = []
        current = start
        while current
          if (index = path.index(current))
            return path[index..]
          end
          path << current
          current = effective[current]
        end
      end
      nil
    end
  end
end

