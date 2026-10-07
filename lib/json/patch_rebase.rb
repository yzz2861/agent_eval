# frozen_string_literal: true

require "json"

module JSON
  # = JSON::PatchRebase
  #
  # Rebase an RFC 6902 (JSON Patch) change set onto a document that has
  # already been modified by another patch.
  #
  # Two editors started from the same base document and each produced a
  # patch. The first patch (+applied+) has already been executed; this
  # module decides whether the second patch (+patch+) can still run and
  # rewrites the paths that are affected by the first patch's array
  # insertions, removals and moves.
  #
  #   result = JSON::PatchRebase.rebase(
  #     base:     { "list" => [1, 2, 3] },
  #     applied:  [{ "op" => "add", "path" => "/list/0", "value" => 0 }],
  #     patch:    [{ "op" => "replace", "path" => "/list/1", "value" => 9 }],
  #   )
  #   result.ok?       # => true
  #   result.patch     # => [{ "op" => "replace", "path" => "/list/2", "value" => 9 }]
  #   result.document  # => { "list" => [0, 1, 9, 3] }
  #
  # Only the six RFC 6902 operations are supported: +add+, +remove+,
  # +replace+, +move+, +copy+ and +test+. No business-level merge rules
  # are guessed: when both patches touch the same value in incompatible
  # ways, the operation is reported as a conflict with its original
  # (zero-based) operation number and no rebased patch is produced.
  #
  # == Conflict reasons
  #
  # [:+target_changed+]   both patches change the same value differently
  # [:+target_removed+]   the first patch removed the target element
  # [:+ancestor_removed+] the first patch removed an ancestor of the target
  # [:+ancestor_changed+] the first patch replaced an ancestor of the target
  # [:+source_changed+]   the first patch removed, replaced or moved the
  #                       +move+/+copy+ source (or one of its ancestors)
  # [:+test_failed+]      the first patch changed the value a +test+ asserts
  #
  # == Redundancy
  #
  # An operation of the second patch that repeats an identical change of
  # the first patch (the same +remove+, or an +add+/+replace+ of the same
  # member with an equal value) is dropped as redundant and reported in
  # Result#notes; it is not a conflict.
  module PatchRebase
    class Error < StandardError; end

    # Raised when +applied+ or +patch+ is not a valid RFC 6902 patch for
    # the document it is applied to.
    class InvalidPatch < Error; end

    # A merge conflict for one operation of the second patch.
    #
    # * +index+: zero-based number of the operation in the original patch
    # * +op+: the original operation (Hash with String keys)
    # * +reason+: one of the reason symbols listed above
    # * +message+: human readable explanation
    Conflict = Struct.new(:index, :op, :reason, :message, keyword_init: true)

    # A non-fatal remark about an operation of the second patch, e.g. an
    # operation that was dropped because the first patch already did the
    # same thing. +index+ is the original zero-based operation number.
    Note = Struct.new(:index, :op, :message, keyword_init: true)

    # The outcome of JSON::PatchRebase.rebase.
    #
    # When the second patch could be rebased, #status is :ok, #patch holds
    # the rebased patch (executable on the document produced by the first
    # patch), #origins maps each rebased operation back to its original
    # zero-based operation number, and #document is the merged document.
    #
    # When at least one operation conflicts, #status is :conflict, #patch
    # and #document are nil, and #conflicts lists every conflicting
    # operation with its original operation number.
    class Result
      attr_reader :status, :patch, :origins, :conflicts, :notes, :document

      def initialize(status:, patch:, origins:, conflicts:, notes:, document:)
        @status = status
        @patch = patch
        @origins = origins
        @conflicts = conflicts
        @notes = notes
        @document = document
      end

      def ok?
        @status == :ok
      end

      def conflict?
        @status == :conflict
      end
    end

    class << self
      # Rebase +patch+ over +applied+, both RFC 6902 patches expressed
      # against the common base document +base+.
      #
      # Returns a Result. Raises InvalidPatch if either patch is not a
      # valid RFC 6902 patch for +base+.
      def rebase(base:, applied:, patch:)
        Rebaser.new.rebase(base, applied, patch)
      end

      # Validate and apply an RFC 6902 +patch+ to +document+, returning a
      # new document. Raises InvalidPatch if the patch does not apply.
      def apply(document, patch)
        ops = Rebaser.normalize_patch(patch)
        Applier.new(deep_copy(document)).apply_all(ops)
      end

      def deep_copy(value) # :nodoc:
        Marshal.load(Marshal.dump(value))
      end
    end

    # RFC 6901 JSON Pointer parsing and formatting. Pointers are handled
    # as arrays of unescaped String tokens.
    module Pointer
      module_function

      def parse(pointer)
        unless pointer.is_a?(String)
          raise InvalidPatch, "invalid JSON Pointer: #{pointer.inspect}"
        end
        return [] if pointer.empty?
        unless pointer.start_with?("/")
          raise InvalidPatch, "invalid JSON Pointer: #{pointer.inspect}"
        end
        pointer.split("/", -1)[1..-1].map do |token|
          token.gsub("~1", "/").gsub("~0", "~")
        end
      end

      def build(segments)
        segments.map do |segment|
          "/" + segment.to_s.gsub("~", "~0").gsub("/", "~1")
        end.join
      end

      def proper_prefix?(prefix, path)
        prefix.size < path.size && path[0...prefix.size] == prefix
      end
    end

    # Validates and applies RFC 6902 operations against a mutable
    # document, raising InvalidPatch when an operation does not apply.
    class Applier
      INDEX = /\A(0|[1-9]\d*)\z/

      attr_reader :document

      def initialize(document)
        @document = document
      end

      def apply_all(ops)
        ops.each { |op| apply(op) }
        @document
      end

      def apply(op)
        case op[:op]
        when :add
          @document = add(@document, op[:path], op[:value])
        when :remove
          @document = remove(@document, op[:path])
        when :replace
          @document = replace(@document, op[:path], op[:value])
        when :move
          apply_move(op)
        when :copy
          value = resolve(@document, op[:from])
          @document = add(@document, op[:path], PatchRebase.deep_copy(value))
        when :test
          actual = resolve(@document, op[:path])
          unless actual == op[:value]
            raise InvalidPatch,
                  "test operation failed at #{Pointer.build(op[:path]).inspect}"
          end
        else
          raise InvalidPatch, "unsupported operation: #{op[:op].inspect}"
        end
      end

      def resolve(document, segments)
        current = document
        segments.each do |token|
          case current
          when Array
            index = array_index(token)
            unless index && index < current.length
              raise InvalidPatch, "invalid array index: #{token.inspect}"
            end
            current = current[index]
          when Hash
            unless current.key?(token)
              raise InvalidPatch, "no such object member: #{token.inspect}"
            end
            current = current[token]
          else
            raise InvalidPatch, "cannot traverse into #{current.inspect}"
          end
        end
        current
      end

      private

      def array_index(token)
        token =~ INDEX ? Integer(token, 10) : nil
      end

      def add(document, segments, value)
        return value if segments.empty?
        parent = resolve(document, segments[0...-1])
        token = segments[-1]
        case parent
        when Array
          if token == "-"
            parent << value
          else
            index = array_index(token)
            unless index && index <= parent.length
              raise InvalidPatch, "invalid array index: #{token.inspect}"
            end
            parent.insert(index, value)
          end
        when Hash
          parent[token] = value
        else
          raise InvalidPatch, "cannot add into #{parent.inspect}"
        end
        document
      end

      def remove(document, segments)
        raise InvalidPatch, "cannot remove the document root" if segments.empty?
        parent = resolve(document, segments[0...-1])
        token = segments[-1]
        case parent
        when Array
          index = array_index(token)
          unless index && index < parent.length
            raise InvalidPatch, "invalid array index: #{token.inspect}"
          end
          parent.delete_at(index)
        when Hash
          unless parent.key?(token)
            raise InvalidPatch, "no such object member: #{token.inspect}"
          end
          parent.delete(token)
        else
          raise InvalidPatch, "cannot remove from #{parent.inspect}"
        end
        document
      end

      def replace(document, segments, value)
        return value if segments.empty?
        parent = resolve(document, segments[0...-1])
        token = segments[-1]
        case parent
        when Array
          index = array_index(token)
          unless index && index < parent.length
            raise InvalidPatch, "invalid array index: #{token.inspect}"
          end
          parent[index] = value
        when Hash
          unless parent.key?(token)
            raise InvalidPatch, "no such object member: #{token.inspect}"
          end
          parent[token] = value
        else
          raise InvalidPatch, "cannot replace in #{parent.inspect}"
        end
        document
      end

      def apply_move(op)
        from = op[:from]
        raise InvalidPatch, "cannot move the document root" if from.empty?
        if Pointer.proper_prefix?(from, op[:path])
          raise InvalidPatch, "cannot move a value into one of its children"
        end
        value = resolve(@document, from)
        @document = remove(@document, from)
        @document = add(@document, op[:path], value)
      end
    end

    # The rebase engine.
    #
    # The first patch is decomposed into a list of positional "effects"
    # (array insertions, removals, member writes and moves). Every
    # operation of the second patch is folded through those effects: its
    # paths are rewritten and conflicts are detected. After each operation
    # of the second patch, the remaining effects are themselves
    # transformed through that operation, so the coordinate space stays
    # correct even when one patch changes many array positions in a row.
    class Rebaser
      REASONS = {
        target_changed: "both patches change the same value",
        target_removed: "the first patch removed the target",
        ancestor_removed: "the first patch removed an ancestor of the target",
        ancestor_changed: "the first patch replaced an ancestor of the target",
        source_changed: "the first patch changed the move/copy source",
        test_failed: "the first patch changed the tested value",
      }.freeze

      class ConflictSignal < StandardError
        attr_reader :reason

        def initialize(reason, message)
          @reason = reason
          super(message)
        end
      end

      class DedupeSignal < StandardError; end

      class << self
        def normalize_patch(patch)
          unless patch.is_a?(Array)
            raise InvalidPatch, "a patch must be an array of operations"
          end
          patch.map { |op| normalize_op(op) }
        end

        def normalize_op(op)
          unless op.is_a?(Hash)
            raise InvalidPatch, "operation must be an object: #{op.inspect}"
          end
          name = op["op"] || op[:op]
          raise InvalidPatch, "operation is missing \"op\"" if name.nil?
          entry = { op: name.to_sym }
          case entry[:op]
          when :add, :replace, :test
            entry[:path] = Pointer.parse(fetch(op, "path"))
            entry[:value] = fetch(op, "value")
          when :remove
            entry[:path] = Pointer.parse(fetch(op, "path"))
          when :move, :copy
            entry[:path] = Pointer.parse(fetch(op, "path"))
            entry[:from] = Pointer.parse(fetch(op, "from"))
          else
            raise InvalidPatch, "unsupported operation: #{name.inspect}"
          end
          entry
        end

        def to_h(entry)
          result = { "op" => entry[:op].to_s, "path" => Pointer.build(entry[:path]) }
          result["from"] = Pointer.build(entry[:from]) if entry[:from]
          result["value"] = entry[:value] if entry.key?(:value)
          result
        end

        private

        def fetch(op, key)
          if op.key?(key)
            op[key]
          elsif op.key?(key.to_sym)
            op[key.to_sym]
          else
            raise InvalidPatch, "operation is missing #{key.inspect}"
          end
        end
      end

      def rebase(base, applied, patch)
        applied_ops = self.class.normalize_patch(applied)
        patch_ops = self.class.normalize_patch(patch)

        applier_a = Applier.new(PatchRebase.deep_copy(base))
        effects = []
        applied_ops.each do |op|
          effects.concat(effects_of(op, applier_a.document))
          applier_a.apply(op)
        end
        document_a = applier_a.document

        applier_b = Applier.new(PatchRebase.deep_copy(base))
        rebased = []
        origins = []
        conflicts = []
        notes = []

        patch_ops.each_with_index do |op, index|
          emit = false
          begin
            transformed = transform_op(op, effects, applier_b.document)
            emit = true
          rescue ConflictSignal => signal
            conflicts << Conflict.new(
              index: index,
              op: self.class.to_h(op),
              reason: signal.reason,
              message: signal.message
            )
          rescue DedupeSignal
            notes << Note.new(
              index: index,
              op: self.class.to_h(op),
              message: "already applied by the first patch; dropped as redundant"
            )
          end
          if emit
            rebased << transformed
            origins << index
          end
          # The operation's own effects apply in the second patch's
          # timeline whether or not it conflicts or is deduplicated, so
          # the remaining effects keep tracking the right positions.
          update_effects(effects, effects_of(op, applier_b.document), applier_b.document)
          applier_b.apply(op)
        end

        unless conflicts.empty?
          return Result.new(
            status: :conflict,
            patch: nil,
            origins: nil,
            conflicts: conflicts,
            notes: notes,
            document: nil
          )
        end

        merged = Applier.new(PatchRebase.deep_copy(document_a))
        begin
          rebased.each { |op| merged.apply(op) }
        rescue InvalidPatch => error
          raise Error, "rebased patch failed to apply: #{error.message}"
        end

        Result.new(
          status: :ok,
          patch: rebased.map { |op| self.class.to_h(op) },
          origins: origins,
          conflicts: [],
          notes: notes,
          document: merged.document
        )
      end

      private

      # --- effects -----------------------------------------------------

      # The positional footprint of one operation, expressed in the
      # coordinate space right before the operation runs.
      def effects_of(op, document)
        case op[:op]
        when :add
          if array_location?(op[:path], document)
            [{ kind: :insert, segs: op[:path] }]
          else
            [{ kind: :write, segs: op[:path], value: op[:value] }]
          end
        when :remove
          [{ kind: :remove, segs: op[:path] }]
        when :replace
          [{ kind: :write, segs: op[:path], value: op[:value] }]
        when :move
          [{
            kind: :move,
            from: op[:from],
            to: op[:path],
            value: resolve_or_nil(document, op[:from]),
          }]
        when :copy
          if array_location?(op[:path], document)
            [{ kind: :insert, segs: op[:path] }]
          else
            [{ kind: :write, segs: op[:path], value: resolve_or_nil(document, op[:from]) }]
          end
        else
          []
        end
      end

      def update_effects(effects, b_effects, document)
        return if b_effects.empty?
        kept = []
        effects.each do |effect|
          current = effect
          b_effects.each do |b_effect|
            current = current && transform_effect(current, b_effect, document)
          end
          kept << current if current
        end
        effects.replace(kept)
      end

      def transform_effect(effect, b_effect, document)
        case effect[:kind]
        when :insert, :remove, :write
          path = shift_effect_path(effect[:segs], effect[:kind], b_effect, document)
          path == :gone ? nil : effect.merge(segs: path)
        when :move
          # The second patch removed the very element the first patch moved.
          if b_effect[:kind] == :remove && b_effect[:segs] == effect[:from]
            return nil
          end
          from = shift_effect_path(effect[:from], :remove, b_effect, document)
          to_role = array_location?(effect[:to], document) ? :insert : :write
          to = shift_effect_path(effect[:to], to_role, b_effect, document)
          if from == :gone && to == :gone
            nil
          elsif from == :gone
            if to_role == :insert
              { kind: :insert, segs: to }
            else
              { kind: :write, segs: to, value: effect[:value] }
            end
          elsif to == :gone
            { kind: :remove, segs: from }
          else
            effect.merge(from: from, to: to)
          end
        end
      end

      # Positional transform of an effect path through one effect of the
      # second patch. +role+ is the kind of the effect owning the path;
      # it decides ties (the first patch ran first). Returns :gone when
      # the effect is subsumed or its target destroyed.
      def shift_effect_path(path, role, b_effect, document)
        case b_effect[:kind]
        when :remove
          removed = b_effect[:segs]
          return :gone if path == removed && role != :insert
          return :gone if Pointer.proper_prefix?(removed, path)
          array_shift(path, removed, document)
        when :insert
          insert_shift(path, b_effect[:segs], document, role == :insert)
        when :write
          written = b_effect[:segs]
          # A write has no positional effect of its own. It only
          # destroys effects pointing inside a wholesale replaced
          # container, and supersedes an earlier write of the same member.
          return :gone if Pointer.proper_prefix?(written, path)
          return :gone if path == written && role == :write
          path
        when :move
          from = b_effect[:from]
          to = b_effect[:to]
          if path == from || Pointer.proper_prefix?(from, path)
            to + path[from.size..-1]
          else
            shifted = shift_effect_path(path, role, { kind: :remove, segs: from }, document)
            return :gone if shifted == :gone
            if array_location?(to, document)
              shift_effect_path(shifted, role, { kind: :insert, segs: to }, document)
            else
              shift_effect_path(shifted, role, { kind: :write, segs: to }, document)
            end
          end
        end
      end

      # --- second patch transform --------------------------------------

      def transform_op(op, effects, document)
        current = { op: op[:op], path: op[:path].dup }
        current[:from] = op[:from].dup if op[:from]
        current[:value] = op[:value] if op.key?(:value)
        effects.each do |effect|
          current[:from] = shift_source(current[:from], effect, document) if current[:from]
          current[:path] = shift_target(current[:path], effect, document, current)
        end
        current
      end

      def shift_target(path, effect, document, op)
        case effect[:kind]
        when :remove
          removed = effect[:segs]
          if path == removed
            case op[:op]
            when :add, :move, :copy
              path
            when :remove
              raise DedupeSignal
            else
              conflict!(:target_removed, removed)
            end
          elsif Pointer.proper_prefix?(removed, path)
            conflict!(:ancestor_removed, removed)
          else
            array_shift(path, removed, document)
          end
        when :insert
          insert_shift(path, effect[:segs], document, false)
        when :write
          write_target(path, effect[:segs], effect[:value], op)
        when :move
          from = effect[:from]
          to = effect[:to]
          if path == from || Pointer.proper_prefix?(from, path)
            to + path[from.size..-1]
          else
            shifted = array_shift(path, from, document)
            if array_location?(to, document)
              insert_shift(shifted, to, document, false)
            else
              write_target(shifted, to, effect[:value], op)
            end
          end
        end
      end

      def write_target(path, written, value, op)
        if path == written
          case op[:op]
          when :add, :replace
            value == op[:value] ? raise(DedupeSignal) : conflict!(:target_changed, written)
          when :test
            value == op[:value] ? path : conflict!(:test_failed, written)
          else
            conflict!(:target_changed, written)
          end
        elsif Pointer.proper_prefix?(written, path)
          conflict!(:ancestor_changed, written)
        elsif Pointer.proper_prefix?(path, written)
          op[:op] == :test ? conflict!(:test_failed, written) : path
        else
          path
        end
      end

      def shift_source(source, effect, document)
        case effect[:kind]
        when :remove
          removed = effect[:segs]
          if source == removed || Pointer.proper_prefix?(removed, source)
            conflict!(:source_changed, removed)
          end
          array_shift(source, removed, document)
        when :insert
          insert_shift(source, effect[:segs], document, false)
        when :write
          written = effect[:segs]
          if source == written || Pointer.proper_prefix?(written, source)
            conflict!(:source_changed, written)
          end
          source
        when :move
          from = effect[:from]
          to = effect[:to]
          conflict!(:source_changed, from) if source == from
          if Pointer.proper_prefix?(from, source)
            to + source[from.size..-1]
          else
            shifted = array_shift(source, from, document)
            if array_location?(to, document)
              insert_shift(shifted, to, document, false)
            else
              if shifted == to || Pointer.proper_prefix?(to, shifted)
                conflict!(:source_changed, to)
              end
              shifted
            end
          end
        end
      end

      # --- path arithmetic ----------------------------------------------

      # Decrement the array index of +path+ when it follows +removed+
      # (an element removal) inside the same array.
      def array_shift(path, removed, document)
        return path if removed.empty? || path.size < removed.size
        return path unless path[0...removed.size - 1] == removed[0...-1]
        return path unless resolve_or_nil(document, removed[0...-1]).is_a?(Array)
        removed_index = array_index(removed[-1])
        index = array_index(path[removed.size - 1])
        return path unless removed_index && index && index > removed_index
        shifted = path.dup
        shifted[removed.size - 1] = (index - 1).to_s
        shifted
      end

      # Increment the array index of +path+ when an insertion at
      # +inserted+ pushes it forward. With +strict+, an index equal to
      # the insertion point is left alone (used when the owner of +path+
      # ran first).
      def insert_shift(path, inserted, document, strict)
        return path if inserted.empty? || inserted[-1] == "-"
        return path if path.size < inserted.size
        return path unless path[0...inserted.size - 1] == inserted[0...-1]
        return path unless resolve_or_nil(document, inserted[0...-1]).is_a?(Array)
        inserted_index = array_index(inserted[-1])
        index = array_index(path[inserted.size - 1])
        return path unless inserted_index && index
        return path unless strict ? index > inserted_index : index >= inserted_index
        shifted = path.dup
        shifted[inserted.size - 1] = (index + 1).to_s
        shifted
      end

      def array_location?(segments, document)
        return false if segments.empty?
        resolve_or_nil(document, segments[0...-1]).is_a?(Array)
      end

      def array_index(token)
        token =~ Applier::INDEX ? Integer(token, 10) : nil
      end

      def resolve_or_nil(document, segments)
        resolver = Applier.new(nil)
        resolver.resolve(document, segments)
      rescue InvalidPatch
        nil
      end

      def conflict!(reason, segments)
        raise ConflictSignal.new(reason, "#{REASONS[reason]}: #{Pointer.build(segments)}")
      end
    end
  end
end
