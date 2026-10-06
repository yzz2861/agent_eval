# frozen_string_literal: true

require_relative 'scalar_scanner'
require_relative 'class_loader'

module Psych
  ###
  # Provenance tracks where every value in a YAML document ultimately came
  # from: whether it was declared directly, inherited through a +<<+ merge
  # key from an anchor, or overridden by a later explicit value.
  #
  # The regular Ruby objects are loaded exactly as Psych.load would load
  # them (object sharing is preserved and the parse tree is never mutated);
  # the provenance information is computed alongside and can be queried by
  # path:
  #
  #   result = Psych.load_with_provenance(File.read('config.yml'), filename: 'config.yml')
  #   result.data                        #=> same as Psych.load(yaml, aliases: true)
  #   result.provenance.trace('db.pool') #=> [#<Entry ...>, ...]
  #
  # Each trace is a short but complete chain of Entry objects, ordered from
  # the original declaration to the effective source.  Every entry points
  # at the file, line and column (1-based) and records the anchor name when
  # a value was inherited through a merge.
  module Provenance
    ###
    # A single step in the provenance chain of a value.
    #
    # +kind+ is one of:
    #
    # +:declared+::  the value was declared directly at this location
    # +:merged+::    the value was inherited through a +<<+ merge key from
    #              the anchor named +anchor+
    # +:override+:: an explicit declaration replaced an earlier (merged or
    #              declared) value at the same mapping level
    # +:aliased+::  the value is an alias reference to the anchor named
    #              +anchor+; the location points at the anchor definition
    class Entry < Struct.new(:kind, :line, :column, :anchor, :filename, keyword_init: true)
      # "config.yml:12:5", or "12:5" when no filename was given
      def location
        loc = "#{line}:#{column}"
        filename ? "#{filename}:#{loc}" : loc
      end

      def to_s
        case kind
        when :declared
          "declared at #{location}"
        when :merged
          if anchor
            "merged from anchor &#{anchor} at #{location}"
          else
            "merged from inline mapping at #{location}"
          end
        when :override
          "overridden by explicit value at #{location}"
        when :aliased
          "aliased to anchor &#{anchor} defined at #{location}"
        else
          "#{kind} at #{location}"
        end
      end
      alias inspect to_s
    end

    ###
    # The provenance record of a loaded document.  Maps paths (arrays of
    # mapping keys and sequence indices) to chains of Entry objects.
    class Record
      include Enumerable

      def initialize(paths) # :nodoc:
        @paths = paths
      end

      # The full provenance chain for +path+, ordered from the original
      # declaration to the effective source.  +path+ may be an array of
      # segments (['db', 'pool']) or a dot separated string ('db.pool').
      # Returns an empty array for unknown paths.
      def trace(path)
        (@paths[normalize(path)] || []).dup
      end
      alias [] trace

      # The effective source of the value at +path+ (the last entry of its
      # trace), or nil for unknown paths.
      def source(path)
        trace(path).last
      end

      def key?(path)
        @paths.key?(normalize(path))
      end

      # All known paths, as arrays of segments.
      def paths
        @paths.keys
      end

      def each(&block)
        @paths.each(&block)
      end

      private

      def normalize(path)
        case path
        when Array
          path
        else
          path.to_s.split('.').map { |seg| /\A-?\d+\z/.match?(seg) ? seg.to_i : seg }
        end
      end
    end

    ###
    # The result of Provenance.load: the regular Ruby objects plus their
    # provenance record.
    class Result
      # The loaded Ruby objects, identical to what Psych.load returns.
      attr_reader :data

      # The Psych::Provenance::Record for the loaded document.
      attr_reader :provenance

      def initialize(data, provenance) # :nodoc:
        @data = data
        @provenance = provenance
      end
    end

    # Loads +yaml+ like Psych.load and returns a Provenance::Result pairing
    # the loaded data with its provenance record.
    #
    # All Psych.load keyword arguments are forwarded.  Unlike Psych.load,
    # +aliases+ defaults to true, since resolving anchors and merge keys is
    # the point of this API.  +filename+ is used both for error reporting
    # and as the file name shown in provenance entries.
    def self.load(yaml, filename: nil, **kwargs)
      kwargs[:aliases] = true unless kwargs.key?(:aliases)
      data = Psych.load(yaml, filename: filename, **kwargs)
      Result.new(data, from_ast(Psych.parse(yaml), filename: filename))
    end

    # Builds a Provenance::Record from an already parsed AST (a
    # Psych::Nodes::Stream or Psych::Nodes::Document).  The tree is only
    # read, never modified.
    def self.from_ast(node, filename: nil)
      Builder.new(filename).build(node)
    end

    # Walks a YAML AST and records where each value came from, mirroring
    # the merge-key semantics of Psych::Visitors::ToRuby#revive_hash:
    # children are processed in document order, a +<<+ merge writes all of
    # its keys at its own position (later writers win), and inside a merge
    # sequence like <<: [*a, *b] earlier anchors take precedence.
    class Builder # :nodoc:
      Source = Struct.new(:value_node, :events)

      def initialize(filename)
        @filename  = filename
        @anchors    = {} # anchor name => node
        @resolved  = {} # mapping object_id => { key => Source }
        @resolving = {} # object_id => true, cycle guard for resolve_mapping
        @walking   = {} # object_id => true, cycle guard for the path walk
        @paths     = {} # path array => [Entry, ...]
        @scanner   = ScalarScanner.new(ClassLoader.new)
      end

      def build(node)
        collect_anchors(node)
        walk(node, [], [])
        Record.new(@paths)
      end

      private

      def collect_anchors(node)
        # Only definition nodes (mapping/sequence/scalar) introduce anchors;
        # an Alias node's +anchor+ is a reference, not a definition.
        case node
        when Nodes::Mapping, Nodes::Sequence, Nodes::Scalar
          @anchors[node.anchor] = node if node.anchor
        end
        node.children.each { |child| collect_anchors(child) } if node.children
      end

      # Walks the tree recording one entry chain per path.  +inherited+
      # carries the merge events of ancestor mappings, so that a value
      # nested inside a merged mapping still shows how its container
      # arrived here.
      def walk(node, path, inherited)
        case node
        when Nodes::Stream
          node.children.each { |child| walk(child, path, inherited) }
        when Nodes::Document
          walk(node.root, path, inherited)
        when Nodes::Mapping
          return if @walking[node.object_id]

          @walking[node.object_id] = true
          begin
            resolve_mapping(node).each do |key, source|
              child_path = path + [key]
              @paths[child_path] = source.events + inherited
              walk_value(source.value_node, child_path, inherited + merge_events_of(source.events))
            end
          ensure
            @walking.delete(node.object_id)
          end
        when Nodes::Sequence
          return if @walking[node.object_id]

          @walking[node.object_id] = true
          begin
            node.children.each_with_index do |child, index|
              element_path = path + [index]
              events = inherited
              events = events + [entry(:declared, child)] if child.is_a?(Nodes::Scalar)
              @paths[element_path] = events
              walk_value(child, element_path, merge_events_of(events))
            end
          ensure
            @walking.delete(node.object_id)
          end
        end
      end

      def merge_events_of(events)
        events.select { |event| event.kind == :merged }
      end

      def walk_value(node, path, inherited)
        node = @anchors[node.anchor] while node.is_a?(Nodes::Alias) && @anchors[node.anchor]
        walk(node, path, inherited) if node
      end

      # Resolves a mapping node to its effective { key => Source } hash,
      # applying merge keys with the same priority as Psych itself.
      def resolve_mapping(node)
        oid = node.object_id
        return @resolved[oid] if @resolved.key?(oid)
        return {} if @resolving[oid] # merge cycle: contributes no keys

        @resolving[oid] = true
        begin
          result = {}
          node.children.each_slice(2) do |key_node, value_node|
            key = key_for(key_node)
            if merge_key?(key_node, key)
              apply_merge(result, value_node)
            else
              declare(result, key, value_node)
            end
          end
          @resolved[oid] = result
        ensure
          @resolving.delete(oid)
        end
      end

      def declare(result, key, value_node)
        events =
          if result.key?(key)
            result[key].events + [entry(:override, value_node)]
          else
            [declaration_entry(value_node)]
          end
        result[key] = Source.new(value_node, events)
      end

      def declaration_entry(value_node)
        if value_node.is_a?(Nodes::Alias) && (target = @anchors[value_node.anchor])
          entry(:aliased, target, anchor: value_node.anchor)
        else
          entry(:declared, value_node)
        end
      end

      def apply_merge(result, value_node)
        sources = merge_sources(value_node)
        # A merge value that does not resolve to mapping(s) is stored under
        # a literal '<<' key, mirroring Psych's TypeError fallback.
        return declare(result, '<<', value_node) unless sources

        sources.each do |location_node, target|
          resolve_mapping(target).each do |key, source|
            merged = entry(:merged, location_node, anchor: target.anchor)
            result[key] = Source.new(source.value_node, source.events + [merged])
          end
        end
      end

      # Returns [location_node, target_mapping] pairs in application order
      # (lowest priority first), or nil when the merge value does not
      # resolve to one or more mappings.
      def merge_sources(value_node)
        case value_node
        when Nodes::Alias
          target = @anchors[value_node.anchor]
          [[value_node, target]] if target.is_a?(Nodes::Mapping)
        when Nodes::Mapping
          [[value_node, value_node]]
        when Nodes::Sequence
          pairs = value_node.children.reverse.map do |child|
            target = child.is_a?(Nodes::Alias) ? @anchors[child.anchor] : child
            [child, target]
          end
          pairs if pairs.all? { |_, target| target.is_a?(Nodes::Mapping) }
        end
      end

      def merge_key?(key_node, key)
        key == '<<' && key_node.tag != 'tag:yaml.org,2002:str'
      end

      def key_for(node)
        case node
        when Nodes::Scalar
          node.quoted ? node.value : @scanner.tokenize(node.value)
        when Nodes::Alias
          target = @anchors[node.anchor]
          key_for(target) if target.is_a?(Nodes::Scalar)
        end
      end

      def entry(kind, node, anchor: nil)
        Entry.new(
          kind:     kind,
          line:     node.start_line && node.start_line + 1,
          column:   node.start_column && node.start_column + 1,
          anchor:   anchor,
          filename: @filename
        )
      end
    end
  end

  ###
  # call-seq:
  #   Psych.load_with_provenance(yaml, filename: 'config.yml') -> Psych::Provenance::Result
  #
  # Like Psych.load, but returns a Psych::Provenance::Result that pairs the
  # loaded data with a provenance record.  See Psych::Provenance.load.
  def self.load_with_provenance(yaml, filename: nil, **kwargs)
    Provenance.load(yaml, filename: filename, **kwargs)
  end
end
