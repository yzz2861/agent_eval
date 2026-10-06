# frozen_string_literal: true

module Psych
  class SourceMap
    class Location
      attr_reader :file, :line, :column, :anchor

      def initialize(file, line, column, anchor)
        @file = file
        @line = line
        @column = column
        @anchor = anchor
      end
    end

    class Step < Location
      attr_reader :kind

      def initialize(kind, file, line, column, anchor, cycle)
        super(file, line, column, anchor)
        @kind = kind
        @cycle = cycle
      end

      def cycle?
        @cycle
      end

      def alias?
        kind == :alias
      end

      def merge?
        kind == :merge
      end

      def to_h
        {
          kind: kind,
          file: file,
          line: line,
          column: column,
          anchor: anchor,
          cycle: cycle?
        }
      end
    end

    class Source < Location
      attr_accessor :path, :declaration_path
      attr_reader :kind, :via, :overrides

      def initialize(path, declaration_path, kind, file, line, column, anchor,
                     via, overrides, overridden)
        super(file, line, column, anchor)
        @path = path.dup
        @declaration_path = declaration_path.dup
        @kind = kind
        @via = via
        @overrides = overrides
        @overridden = overridden
      end

      def direct?
        kind == :direct
      end

      def aliased?
        kind == :alias
      end

      def inherited?
        kind == :inherited
      end

      def cycle?
        via.any?(&:cycle?)
      end

      def overridden?
        @overridden
      end

      def to_h
        {
          path: path,
          declaration_path: declaration_path,
          kind: kind,
          file: file,
          line: line,
          column: column,
          anchor: anchor,
          via: via.map(&:to_h),
          overrides: overrides.map(&:to_h)
        }
      end
      alias_method :to_hash, :to_h
    end

    def initialize(document, filename: nil, symbolize_names: false,
                   scanner: nil, class_loader: nil, strict_integer: false,
                   parse_symbols: true)
      @file = filename || "<unknown>"
      @symbolize_names = symbolize_names
      @class_loader = class_loader || ClassLoader.new
      @scanner = scanner || ScalarScanner.new(
        @class_loader,
        strict_integer: strict_integer,
        parse_symbols: parse_symbols
      )
      @root = root_from(document)
      @anchors = {}
      @nearest_anchors = {}
      @parents = {}
      @entries_cache = {}
      analyze(@root) if @root
    end

    def source_for(*path)
      segments = normalize_path(path)
      return nil unless @root

      node = @root
      steps = []
      active_nodes = {}

      if node.is_a?(Nodes::Alias)
        target = anchor_target(node)
        steps << build_step(:alias, node, active_nodes.key?(target.object_id))
        node = target
      end
      active_nodes[node.object_id] = true if node

      resolved = resolve(node, segments, steps, active_nodes, {})
      return nil unless resolved

      origin, origin_steps, origin_overrides = resolved
      source = make_source(source_kind(origin_steps), origin, origin_steps,
                           origin_overrides, false)
      assign_paths(source, segments)
      source
    end

    alias_method :[], :source_for
    alias_method :source_at, :source_for

    private

    def root_from(document)
      return nil unless document
      return document.root if document.is_a?(Nodes::Document)
      if document.is_a?(Nodes::Stream) && !document.children.empty?
        return document.children.first.root
      end
      document
    end

    def analyze(node, inherited_anchor = nil)
      anchor = inherited_anchor
      if declaration_node?(node) && node.anchor
        @anchors[node.anchor] = node
        anchor = node.anchor
      end
      @nearest_anchors[node.object_id] = anchor
      (node.children || []).each do |child|
        @parents[child.object_id] = node
        analyze(child, anchor)
      end
    end

    def declaration_node?(node)
      node.is_a?(Nodes::Scalar) || node.is_a?(Nodes::Sequence) ||
        node.is_a?(Nodes::Mapping)
    end

    def normalize_path(path)
      if path.length == 1 && Array === path.first
        path.first.to_a
      else
        path
      end
    end

    def resolve(node, segments, steps, active_nodes, active_merges)
      return nil unless node

      if node.is_a?(Nodes::Mapping)
        resolve_mapping(node, segments, steps, active_nodes, active_merges)
      elsif node.is_a?(Nodes::Sequence)
        resolve_sequence(node, segments, steps, active_nodes, active_merges)
      elsif node.is_a?(Nodes::Alias)
        resolve_alias(node, segments, steps, active_nodes, active_merges, :alias)
      elsif segments.empty?
        [node, steps, []]
      end
    end

    def resolve_mapping(node, segments, steps, active_nodes, active_merges)
      return [node, steps, []] if segments.empty?

      entries = entries_for(node)
      key = segments.first
      remaining = segments.drop(1)
      direct_entries = entries[:direct][key]

      if direct_entries && !direct_entries.empty?
        winner = resolve_entry(direct_entries.last, remaining, steps,
                               active_nodes, active_merges)
        return nil unless winner

        overrides = earlier_direct_overrides(
          direct_entries, remaining, steps, active_nodes, active_merges
        ) + merge_overrides(
          entries[:merge], segments, steps, active_nodes, active_merges
        )
        origin, origin_steps, origin_overrides = winner
        [origin, origin_steps, origin_overrides + overrides]
      else
        merge_winner = nil
        losers = []

        entries[:merge].each do |candidate|
          resolved = resolve_merge(candidate, segments, steps, active_nodes,
                                   active_merges)
          next unless resolved

          if merge_winner.nil?
            merge_winner = resolved
          else
            origin, origin_steps, origin_overrides = resolved
            losers << make_source(source_kind(origin_steps), origin,
                                  origin_steps, origin_overrides, true)
          end
        end

        return nil unless merge_winner
        origin, origin_steps, origin_overrides = merge_winner
        [origin, origin_steps, origin_overrides + losers]
      end
    end

    def resolve_sequence(node, segments, steps, active_nodes, active_merges)
      return [node, steps, []] if segments.empty?
      index = segments.first
      return nil unless Integer === index

      resolve_entry_node(node.children[index], segments.drop(1), steps,
                         active_nodes, active_merges)
    end

    def resolve_entry(entry, remaining, steps, active_nodes, active_merges)
      resolve_entry_node(entry[:node], remaining, steps, active_nodes,
                         active_merges)
    end

    def resolve_entry_node(node, remaining, steps, active_nodes, active_merges)
      return nil unless node
      if node.is_a?(Nodes::Alias)
        resolve_alias(node, remaining, steps, active_nodes, active_merges, :alias)
      else
        with_active_node(node, active_nodes) do
          resolve(node, remaining, steps, active_nodes, active_merges)
        end
      end
    end

    def resolve_alias(node, remaining, steps, active_nodes, active_merges, kind)
      target = anchor_target(node)
      return nil unless target

      cycle = active_nodes.key?(target.object_id)
      steps = steps + [build_step(kind, node, cycle)]

      with_active_node(target, active_nodes) do
        resolve(target, remaining, steps, active_nodes, active_merges)
      end
    end

    def resolve_merge(candidate, segments, steps, active_nodes, active_merges)
      provider = candidate[:provider]
      state = [provider.object_id, segments]
      return nil if active_merges[state]

      via = candidate[:via]
      cycle = active_nodes.key?(provider.object_id)
      steps = steps + [build_step(:merge, via, cycle)]

      active_merges[state] = true
      begin
        with_active_node(provider, active_nodes) do
          resolve(provider, segments, steps, active_nodes, active_merges)
        end
      ensure
        active_merges.delete(state)
      end
    end

    def earlier_direct_overrides(entries, path, steps, active_nodes, active_merges)
      entries[0...-1].flat_map do |entry|
        resolved = resolve_entry(entry, path, steps, active_nodes, active_merges)
        next [] unless resolved
        origin, origin_steps, origin_overrides = resolved
        [make_source(source_kind(origin_steps), origin,
                     origin_steps, origin_overrides, true)]
      end
    end

    def merge_overrides(candidates, segments, steps, active_nodes, active_merges)
      candidates.flat_map do |candidate|
        resolved = resolve_merge(candidate, segments, steps, active_nodes,
                                 active_merges)
        next [] unless resolved
        origin, origin_steps, origin_overrides = resolved
        [make_source(source_kind(origin_steps), origin, origin_steps,
                     origin_overrides, true)]
      end
    end

    def with_active_node(node, active_nodes)
      id = node.object_id
      already_active = active_nodes.key?(id)
      active_nodes[id] = true
      begin
        yield
      ensure
        active_nodes.delete(id) unless already_active
      end
    end

    def entries_for(node)
      @entries_cache[node.object_id] ||= begin
        entries = { direct: Hash.new { |hash, key| hash[key] = [] }, merge: [] }
        node.children.each_slice(2).with_index do |(key_node, value_node), index|
          if merge_key?(key_node)
            providers = merge_providers(value_node)
            if providers.empty?
              entries[:direct][key_value(key_node)] << { node: value_node, index: index }
            else
              providers.each do |provider|
                entries[:merge] << provider.merge(pair_index: index)
              end
            end
          else
            entries[:direct][key_value(key_node)] << { node: value_node, index: index }
          end
        end
        entries
      end
    end

    def merge_key?(node)
      node.is_a?(Nodes::Scalar) && node.value == '<<' &&
        node.tag != 'tag:yaml.org,2002:str'
    end

    def merge_providers(node)
      case node
      when Nodes::Alias
        target = anchor_target(node)
        hash_mapping?(target) ? [{ provider: target, via: node }] : []
      when Nodes::Mapping
        hash_mapping?(node) ? [{ provider: node, via: node }] : []
      when Nodes::Sequence
        node.children.each_with_object([]) do |child, providers|
          target = child.is_a?(Nodes::Alias) ? anchor_target(child) : child
          return [] unless hash_mapping?(target)
          providers << { provider: target, via: child }
        end
      else
        []
      end
    end

    def hash_mapping?(node)
      return false unless node.is_a?(Nodes::Mapping)
      return true if node.tag.nil?
      node.tag == 'tag:yaml.org,2002:map' || node.tag == '!map' ||
        node.tag == '!omap' || node.tag == 'tag:yaml.org,2002:omap' ||
        node.tag == '!set' || node.tag == 'tag:yaml.org,2002:set' ||
        node.tag.start_with?('!ruby/hash-with-ivars',
                             'tag:yaml.org,2002:hash-with-ivars:') ||
        node.tag.start_with?('!map:', '!ruby/hash:') ||
        node.tag.start_with?('tag:yaml.org,2002:map:')
    end

    def key_value(node)
      node = anchor_target(node) if node.is_a?(Nodes::Alias)
      return nil unless node.is_a?(Nodes::Scalar)
      value = if node.quoted || node.tag == 'tag:yaml.org,2002:str'
                node.value
              else
                @scanner.tokenize(node.value)
              end
      value = value.to_sym if @symbolize_names && value.is_a?(String)
      value
    end

    def anchor_target(node)
      @anchors[node.anchor]
    end

    def build_step(kind, node, cycle)
      anchor = node.respond_to?(:anchor) ? node.anchor : nil
      Step.new(kind, @file, node.start_line, node.start_column, anchor, cycle)
    end

    def make_source(kind, origin, steps, overrides, overridden)
      anchor = origin.respond_to?(:anchor) ? origin.anchor : nil
      anchor ||= @nearest_anchors[origin.object_id]
      Source.new([], physical_path(origin), kind, @file,
                 origin.start_line, origin.start_column, anchor, steps,
                 overrides, overridden)
    end

    def assign_paths(source, path)
      source.path = path.dup
      source.overrides.each { |candidate| assign_paths(candidate, path) }
    end

    def physical_path(node)
      segments = []
      current = node

      while current && current != @root
        parent = @parents[current.object_id]
        break unless parent

        index = parent.children.index(current)
        if parent.is_a?(Nodes::Mapping) && index
          segments << key_value(parent.children[index - 1]) if index.odd?
        elsif index
          segments << index
        end
        current = parent
      end

      segments.reverse
    end

    def source_kind(steps)
      if steps.any?(&:merge?)
        :inherited
      elsif steps.any?(&:alias?)
        :alias
      else
        :direct
      end
    end

  end
end
