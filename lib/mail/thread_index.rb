# encoding: utf-8
# frozen_string_literal: true

require 'set'

module Mail
  # Incrementally indexes mail messages by their References and In-Reply-To
  # headers.
  #
  # Referenced messages do not have to arrive before the messages that refer to
  # them. Missing ancestors are kept as placeholder nodes and filled in when the
  # real message is later added. Subjects are intentionally ignored: matching
  # subjects alone do not prove that messages belong to the same discussion.
  #
  # Parent selection is deterministic:
  #
  # 1. A single In-Reply-To ID is the immediate parent.
  # 2. When several In-Reply-To IDs are present, the last one that also occurs
  #    in References is preferred; if none overlaps, the first In-Reply-To ID
  #    is used.
  # 3. If no usable In-Reply-To ID exists, the last ID in References is used.
  # 4. A reference loop is broken at the lexicographically smallest ID in the
  #    loop so traversal remains a forest and results do not depend on arrival
  #    order.
  class ThreadIndex
    Node = Struct.new(:message_id, :message, keyword_init: true) do
      def placeholder?
        message.nil?
      end
    end

    Conflict = Struct.new(:message_id, :messages, keyword_init: true)

    Structure = Struct.new(:parents, :children, :roots, keyword_init: true)

    def initialize
      @nodes = {}
      @direct_parents = {}
      @inferred_parents = Hash.new { |hash, id| hash[id] = Set.new }
      @referenced_ids = Hash.new { |hash, id| hash[id] = Set.new }
      @conflicts = {}
      @structure = nil
    end

    # Adds a message and every referenced ancestor that has not been seen yet.
    # Placeholder ancestors are merged automatically when their message arrives.
    def add(message)
      unless message.respond_to?(:message_id) && !message.message_id.nil?
        raise ArgumentError, 'message must have a Message-ID'
      end

      id = message.message_id
      node = @nodes[id]

      if node
        if node.message.nil?
          node.message = message
        elsif node.message != message
          record_conflict(id, message)
          @structure = nil
          return self
        else
          return self
        end
      else
        node = Node.new(message_id: id, message: message)
        @nodes[id] = node
      end

      in_reply_to = message_ids(message, :in_reply_to)
      references = message_ids(message, :references)
      referenced = Set.new
      referenced.merge(in_reply_to)
      referenced.merge(references)
      @referenced_ids[id] = referenced
      referenced.each { |referenced_id| ensure_node(referenced_id) unless referenced_id == id }

      add_references_chain(id, references)

      direct_parent = direct_parent(id, in_reply_to, references)
      if direct_parent
        ensure_node(direct_parent)
      end
      @direct_parents[id] = direct_parent

      @structure = nil
      self
    end
    alias_method :add_message, :add

    def size
      @nodes.size
    end

    def node?(id)
      @nodes.key?(id)
    end

    def node(id)
      @nodes[id]
    end

    def message(id)
      node = @nodes[id]
      node.message if node
    end

    def placeholder?(id)
      node = @nodes[id]
      node ? node.placeholder? : false
    end

    def nodes
      sorted_ids.map { |id| @nodes[id] }
    end

    def messages
      nodes.reject(&:placeholder?).map(&:message)
    end

    def root_ids
      structure.roots
    end

    def roots
      values_at(structure.roots)
    end

    def parent_id(id)
      fetch_node(id)
      structure.parents[id]
    end

    def parent(id)
      parent_id = parent_id(id)
      @nodes[parent_id] if parent_id
    end

    def child_ids(id)
      fetch_node(id)
      structure.children[id].dup
    end

    def children(id)
      values_at(child_ids(id))
    end

    # Returns resolved parent/child pairs as parent_id => child_ids. IDs in each
    # pair and the returned pairs are sorted for stable output.
    def parent_relationships
      structure.children.each_with_object({}) do |(parent_id, child_ids), relationships|
        relationships[parent_id] = child_ids.dup
      end
    end

    def unresolved_message_ids
      sorted_ids.select { |id| @nodes[id].placeholder? }
    end

    # Returns the IDs still referenced by each known message whose referenced
    # node remains a placeholder. This includes missing indirect ancestors, not
    # only the selected immediate parent.
    def unresolved_references
      @referenced_ids.keys.sort.each_with_object({}) do |id, result|
        missing = @referenced_ids[id].to_a.sort.select do |referenced_id|
          referenced_node = @nodes[referenced_id]
          referenced_node.nil? || referenced_node.placeholder?
        end
        result[id] = missing if missing.any?
      end
    end

    def conflicts
      @conflicts.keys.sort.map do |id|
        Conflict.new(
          message_id: id,
          messages: @conflicts[id].sort_by { |message| conflict_key(message) }
        )
      end
    end

    def conflict?(id = nil)
      if id
        @conflicts.key?(id)
      else
        @conflicts.any?
      end
    end

    private
      def structure
        @structure ||= build_structure
      end

      def build_structure
        rejected = Set.new
        parents = {}

        loop do
          parents = sorted_ids.each_with_object({}) do |id, result|
            result[id] = candidate_parent(id, rejected)
          end

          cycles = detect_cycles(parents)
          break if cycles.empty?

          cycles.each do |cycle|
            smallest_id = cycle.min
            rejected << [smallest_id, parents[smallest_id]]
          end
        end

        children = sorted_ids.each_with_object({}) do |id, result|
          result[id] = []
        end

        parents.each do |id, parent_id|
          children[parent_id] << id if parent_id
        end

        roots = parents.select { |_, parent_id| parent_id.nil? }.keys.sort
        Structure.new(
          parents: parents.freeze,
          children: children.each_value(&:sort!).freeze,
          roots: roots.freeze
        )
      end

      def candidate_parent(id, rejected)
        candidates = parent_candidates(id)
        candidates.find do |candidate_id|
          candidate_id != id &&
            @nodes.key?(candidate_id) &&
            !rejected.include?([id, candidate_id])
        end
      end

      def parent_candidates(id)
        if @direct_parents.key?(id)
          [@direct_parents[id]].compact
        else
          @inferred_parents[id].to_a.sort
        end
      end

      def detect_cycles(parents)
        state = {}
        cycles = []
        signatures = Set.new

        sorted_ids.each do |start_id|
          next if state[start_id] == :done

          path = []
          positions = {}
          id = start_id

          while id
            case state[id]
            when :done
              break
            when :active
              cycle = path[positions[id]..-1]
              signature = cycle.sort
              cycles << cycle unless signatures.include?(signature)
              signatures << signature
              break
            end

            state[id] = :active
            positions[id] = path.size
            path << id
            id = parents[id]
          end

          path.each { |path_id| state[path_id] = :done }
        end

        cycles
      end

      def direct_parent(id, in_reply_to, references)
        candidates = []

        if in_reply_to.one?
          candidates << in_reply_to.first
        elsif in_reply_to.any?
          common = in_reply_to & references
          candidates << (common.any? ? common.last : in_reply_to.first)
        end

        candidates.concat(references.reverse) if references.any?
        candidates.uniq.find { |candidate_id| candidate_id != id }
      end

      def add_references_chain(id, references)
        chain = references.each_with_object([]) do |referenced_id, result|
          next if referenced_id == id
          next if result.last == referenced_id

          ensure_node(referenced_id)
          result << referenced_id
        end

        chain.each_cons(2) do |parent_id, child_id|
          next if parent_id == child_id

          ensure_node(parent_id)
          ensure_node(child_id)
          @inferred_parents[child_id] << parent_id
        end
      end

      def ensure_node(id)
        @nodes[id] ||= Node.new(message_id: id, message: nil)
      end

      def message_ids(message, name)
        field = message[name]
        return [] unless field.respond_to?(:message_ids)

        Array(field.message_ids).compact
      end

      def record_conflict(id, message)
        @conflicts[id] ||= [@nodes[id].message]
        return if @conflicts[id].any? { |existing| existing == message }

        @conflicts[id] << message
      end

      def conflict_key(message)
        message.dup.tap do |duplicate|
          duplicate.date ||= Mail::CommonDateField.normalize_datetime('')
        end.encoded
      end

      def sorted_ids
        @nodes.keys.sort
      end

      def values_at(ids)
        ids.map { |id| @nodes[id] }
      end

      def fetch_node(id)
        @nodes.fetch(id) { raise ArgumentError, %(unknown message ID #{id.inspect}) }
      end
  end
end
