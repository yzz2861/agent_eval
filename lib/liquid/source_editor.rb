# frozen_string_literal: true

require "liquid/source_map"

module Liquid
  # Performs local, source-preserving edits on a parsed Template.
  #
  # Rather than regenerating the template (which would reformat it), an editor
  # accumulates byte-span replacements against the original source. Replacements
  # are validated against a fresh SourceMap before they are accepted, and the
  # result is re-parsed so that subsequent edits resolve against the new
  # bindings. Bytes outside every edit are copied through untouched, preserving
  # CRLF, whitespace-control hyphens and irregular indentation exactly.
  class SourceEditor
    # One pending [start_byte, end_byte, replacement] triple.
    Edit = Struct.new(:start_byte, :end_byte, :replacement, :label, keyword_init: true)

    attr_reader :source_map

    def initialize(template, environment: template.instance_variable_get(:@environment) || Environment.default)
      @template = template
      @environment = environment
      @source_map = template.source_map
    end

    # Renames every occurrence of the variable binding visible at `at_byte`
    # (a byte offset) to `new_name`. Returns the number of bytes replaced.
    #
    # When a binding for `name` is supplied instead of an offset, all of that
    # binding's occurrences (including its declaration) are renamed. Strings,
    # comments, raw bodies, property names and dynamic (quoted) keys are left
    # untouched.
    def rename_variable(name, new_name, at_byte: nil, binding: nil)
      target = binding || resolve_binding(name, at_byte)
      raise ArgumentError, "no variable named #{name.inspect} at the given position" unless target
      raise ArgumentError, "new name must be a valid Liquid identifier" unless valid_identifier?(new_name)

      edits = target.occurrences.map do |occurrence|
        Edit.new(
          start_byte: occurrence.start_byte,
          end_byte: occurrence.end_byte,
          replacement: new_name,
          label: "rename #{name} -> #{new_name}",
        )
      end

      apply_edits(edits)
    end

    # Renames every independently-scoped binding called `name` (e.g. an outer
    # variable and each loop that shadows it). Use this for a whole-document
    # rename. Returns the number of bytes replaced.
    def rename_variable_everywhere(name, new_name)
      bindings = @source_map.bindings_named(name)
      raise ArgumentError, "no variable named #{name.inspect}" if bindings.empty?
      raise ArgumentError, "new name must be a valid Liquid identifier" unless valid_identifier?(new_name)

      edits = bindings.flat_map do |binding|
        binding.occurrences.map do |occurrence|
          Edit.new(start_byte: occurrence.start_byte, end_byte: occurrence.end_byte,
                   replacement: new_name, label: "rename #{name} -> #{new_name}")
        end
      end

      apply_edits(edits)
    end

    # Low-level local replacement of a byte range. The range must lie on a
    # single region boundary and must not overlap another pending edit.
    def replace(start_byte, end_byte, replacement, label: 'replace')
      edit = Edit.new(start_byte: start_byte, end_byte: end_byte,
                      replacement: replacement, label: label)
      validate_edit_bounds(edit)
      apply_edits([edit])
    end

    # Applies accumulated edits and returns the edited source string without
    # mutating the template. Useful for inspection before re-parsing.
    def preview(edits)
      compose(@source_map.source, edits)
    end

    private

    def resolve_binding(name, at_byte)
      if at_byte
        occurrence = @source_map.occurrence_at(at_byte)
        return occurrence&.binding if occurrence&.name == name
        @source_map.binding_for(name, at_byte)
      else
        bindings = @source_map.bindings_named(name)
        bindings.first
      end
    end

    def valid_identifier?(value)
      value.is_a?(String) && value.match?(/\A[a-zA-Z_][\w-]*\z/)
    end

    def validate_edit_bounds(edit)
      source = @source_map.source
      unless edit.start_byte.is_a?(Integer) && edit.end_byte.is_a?(Integer) &&
             edit.start_byte >= 0 && edit.end_byte <= source.bytesize &&
             edit.end_byte >= edit.start_byte
        raise ArgumentError, "edit #{edit.label.inspect} is out of bounds"
      end
    end

    # Validates non-overlap, composes the new source, re-parses it into the
    # bound template and refreshes the source map.
    def apply_edits(edits)
      edits.each { |edit| validate_edit_bounds(edit) }
      ensure_no_overlap(edits)

      previous_source = @source_map.source
      new_source = compose(previous_source, edits)

      # Re-parse validates that the edited template is still well formed. On
      # failure the template and its source map are left untouched so the edit
      # is all-or-nothing.
      begin
        @template.send(:reparse_from, new_source)
      rescue ::StandardError
        @template.send(:reparse_from, previous_source)
        @source_map = @template.source_map
        raise
      end
      @source_map = @template.source_map(rebuild: true)

      edits.sum { |edit| edit.end_byte - edit.start_byte }
    end

    def ensure_no_overlap(edits)
      sorted = edits.sort_by { |edit| [edit.start_byte, edit.end_byte] }
      sorted.each_cons(2) do |earlier, later|
      if later.start_byte < earlier.end_byte
        raise OverlappingEditError,
          "overlapping edits at bytes #{earlier.start_byte}...#{earlier.end_byte} and #{later.start_byte}...#{later.end_byte}"
      end
      end
    end

    def compose(source, edits)
      sorted = edits.sort_by(&:start_byte)
      output = +''
      cursor = 0

      sorted.each do |edit|
        output << source.byteslice(cursor, edit.start_byte - cursor)
        output << edit.replacement
        cursor = edit.end_byte
      end
      output << source.byteslice(cursor, source.bytesize - cursor)
      output
    end
  end
end
