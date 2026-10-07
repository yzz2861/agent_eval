# -*- ruby encoding: utf-8 -*-
require "base64"
require "stringio"

##
# Streaming LDIF change-record layer (RFC 2849).
#
# Unlike Net::LDAP::Dataset, which materializes whole entry records into
# memory, Net::LDAP::LDIF parses change records from an arbitrary IO and
# yields AddChange, DeleteChange, ModifyChange, and ModifyDNChange objects
# as soon as each record is complete. A record is never yielded before its
# terminating blank line (or end-of-file) has been read, so a partially
# read record can never be acted upon.
#
#   Net::LDAP::LDIF.foreach("changes.ldif") do |change|
#     case change
#     when Net::LDAP::LDIF::AddChange      then ldap.add(change.to_args)
#     when Net::LDAP::LDIF::DeleteChange   then ldap.delete(change.to_args)
#     when Net::LDAP::LDIF::ModifyChange   then ldap.modify(change.to_args)
#     when Net::LDAP::LDIF::ModifyDNChange then ldap.rename(change.to_args)
#     end
#   end
#
# URL-valued lines (":<url") are never fetched implicitly. Supply a
# +resolver:+ callable that receives the URL and returns the value as a
# String; otherwise a LdifError is raised when such a line is encountered.
#
# Use Net::LDAP::LDIF.dump or Net::LDAP::LDIF::Writer to serialize change
# records. Values containing unsafe bytes are base64-encoded and long
# lines are folded per RFC 2849.
class Net::LDAP::LDIF
  SPEC_VERSION = "1"

  ##
  # Raised for malformed LDIF input. Messages identify the 1-based record
  # number and physical line number, e.g. "record 2, line 7: ...".
  class LdifError < Net::LDAP::Error
    attr_reader :record_number, :line_number

    def initialize(message, record_number, line_number)
      @record_number = record_number
      @line_number = line_number
      super("LDIF parse error at record #{record_number}, line #{line_number}: #{message}")
    end
  end

  Error = LdifError

  ##
  # A record-level LDIF control:
  #
  #   control: 1.3.6.1.4.1.4203.666.5.2 true:: Zm9vOgBiYXI=
  #
  # +oid+ is the dotted OID string, +criticality+ is a boolean, and +value+
  # is the raw control value as a binary String, or nil.
  Control = Struct.new(:oid, :criticality, :value) do
    def initialize(oid, criticality = false, value = nil)
      super
    end
  end

  ##
  # Base class for the four kinds of change records. Every change has a
  # +dn+ and an ordered list of record-level #controls.
  class Change
    attr_reader :dn, :controls

    def initialize(dn, controls = [])
      @dn = dn
      @controls = Array(controls)
    end

    def changetype
      self.class::CHANGE_TYPE
    end

    def add?
      is_a?(AddChange)
    end

    def delete?
      is_a?(DeleteChange)
    end

    def modify?
      is_a?(ModifyChange)
    end

    def moddn?
      is_a?(ModifyDNChange)
    end

    # Applies this change against a Net::LDAP connection.
    def apply(ldap)
      ldap.public_send(self.class::LDAP_METHOD, to_args)
    end
  end

  ##
  # An +add:+ change. #attributes is an ordered Hash of downcased Symbol
  # attribute names to Arrays of String values, in file order. A record
  # without a changetype (an ordinary content record) is parsed as an
  # AddChange.
  class AddChange < Change
    CHANGE_TYPE = "add"
    LDAP_METHOD = :add

    attr_reader :attributes

    def initialize(dn, attributes, controls = [])
      super(dn, controls)
      @attributes = attributes
    end

    # Argument hash for Net::LDAP#add.
    def to_args
      args = { :dn => dn, :attributes => attributes }
      args[:controls] = ber_controls unless controls.empty?
      args
    end

    private

    def ber_controls
      controls.map { |control| encode_control(control) }
    end

    def encode_control(control)
      elements = [control.oid.to_s.to_ber,
                  (control.criticality ? true : false).to_ber]
      elements << control.value.to_s.to_ber_bin unless control.value.nil?
      elements.to_ber_sequence
    end
  end

  ##
  # A +delete:+ change.
  class DeleteChange < Change
    CHANGE_TYPE = "delete"
    LDAP_METHOD = :delete

    # Argument hash for Net::LDAP#delete.
    def to_args
      args = { :dn => dn }
      args[:control_codes] = controls.map do |control|
        triple = [control.oid, control.criticality]
        triple << control.value unless control.value.nil?
        triple
      end unless controls.empty?
      args
    end
  end

  ##
  # A +modify:+ change. #operations is the same ordered array of
  # +[action, attribute, values]+ triples accepted by Net::LDAP#modify:
  # +action+ is +:add+, +:delete+, or +:replace+, and +values+ is nil for
  # a value-less delete. Groups separated by a single "-" line in LDIF
  # are represented by the order of the triples; each separator closes
  # the current group before the next begins.
  class ModifyChange < Change
    CHANGE_TYPE = "modify"
    LDAP_METHOD = :modify

    attr_reader :operations

    def initialize(dn, operations, controls = [])
      super(dn, controls)
      @operations = operations
    end

    # Argument hash for Net::LDAP#modify.
    def to_args
      args = { :dn => dn, :operations => operations }
      args[:controls] = ber_controls unless controls.empty?
      args
    end

    private

    def ber_controls
      controls.map do |control|
        elements = [control.oid.to_s.to_ber,
                    (control.criticality ? true : false).to_ber]
        elements << control.value.to_s.to_ber_bin unless control.value.nil?
        elements.to_ber_sequence
      end
    end
  end

  ##
  # A +moddn:+ (or +modrdn:+) change.
  class ModifyDNChange < Change
    CHANGE_TYPE = "moddn"
    LDAP_METHOD = :rename

    attr_reader :newrdn, :delete_old_rdn, :new_superior

    def initialize(dn, newrdn, delete_old_rdn, new_superior = nil, controls = [])
      super(dn, controls)
      @newrdn = newrdn
      @delete_old_rdn = delete_old_rdn
      @new_superior = new_superior
    end

    alias delete_old_rdn? delete_old_rdn

    # Argument hash for Net::LDAP#rename (aliased as modify_rdn).
    def to_args
      args = {
        :olddn => dn,
        :newrdn => newrdn,
        :delete_attributes => delete_old_rdn,
      }
      args[:new_superior] = new_superior unless new_superior.nil?
      args
    end
  end

  ##
  # Reads LDIF change records from an IO object.
  #
  # Input is pulled in fixed-size blocks (default 4096 bytes), so IO
  # objects that return very small chunks (sockets, pipes, StringIO opened
  # over tiny reads) are handled correctly. Folded continuation lines,
  # comments, base64 values, and record-level controls are supported.
  class Reader
    include Enumerable

    DEFAULT_BLOCK_SIZE = 4096

    MODIFY_ACTIONS = {
      "add" => :add,
      "delete" => :delete,
      "replace" => :replace,
    }.freeze

    # Yields each complete change record in +io+; see Net::LDAP::LDIF.foreach.
    def self.foreach(io, resolver: nil, block_size: DEFAULT_BLOCK_SIZE, &block)
      new(io, resolver: resolver, block_size: block_size).each(&block)
    end

    def initialize(io, resolver: nil, block_size: DEFAULT_BLOCK_SIZE)
      if !block_size.is_a?(Integer) || block_size <= 0
        raise ArgumentError, "block_size must be a positive Integer"
      end

      @io = io
      @resolver = resolver
      @block_size = block_size
      @buffer = binary_string
      @eof = false
      @physical_line = 0
      @pending = nil
    end

    # Yields each change record only after its terminating blank line (or
    # end-of-file) has been consumed. Returns an Enumerator without a block.
    def each
      return enum_for(:each) unless block_given?

      record_number = 0
      while (logical = next_logical_line)
        text, start_line = logical
        # Blank and comment lines between records carry no record data.
        next if text.empty? || text.start_with?("#")

        if text =~ /\Aversion\s*:/i
          parse_version(text, start_line, record_number)
          next
        end

        record_number += 1
        yield parse_record(text, start_line, record_number)
      end
      self
    end

    private

    def binary_string
      String.new.force_encoding(Encoding::ASCII_8BIT)
    end

    def parse_version(text, line, records_seen)
      spec = value_spec(text, 0, line)
      unless records_seen.zero? &&
             spec[:name].downcase == "version" &&
             spec[:value] == SPEC_VERSION
        raise LdifError.new("unsupported or misplaced LDIF version directive",
                           records_seen + 1, line)
      end
    end

    # Stitches physical continuation lines (leading SPACE) into one
    # logical line, tracking the physical line at which it started.
    def next_logical_line
      physical = next_physical_line
      return nil unless physical

      text, start_line = physical
      text = text.dup

      while (following = next_physical_line) && following[0].start_with?(" ")
        text << following[0][1..-1].to_s
      end
      @pending = following
      [text, start_line]
    end

    # Returns [content_without_eol, line_number] or nil at EOF. Reads the
    # IO in fixed-size blocks; a line break may straddle two reads.
    def next_physical_line
      if @pending
        line = @pending
        @pending = nil
        return line
      end

      until @eof
        lf = @buffer.index("\n")
        if lf
          return consume_physical_line(lf)
        end
        fill_buffer
      end

      return nil if @buffer.empty?

      line = @buffer
      @buffer = binary_string
      @physical_line += 1
      [line, @physical_line]
    end

    def consume_physical_line(lf)
      content_end = lf
      content_end -= 1 if lf.positive? && @buffer.getbyte(lf - 1) == 13
      content = @buffer.byteslice(0, content_end)
      @buffer = @buffer.byteslice((lf + 1)..-1) || binary_string
      @physical_line += 1
      [content, @physical_line]
    end

    def fill_buffer
      return if @eof

      chunk = @io.read(@block_size)
      if chunk.nil? || chunk.empty?
        @eof = true
      else
        @buffer << chunk
      end
    end

    # Parses a complete record. The first logical line is supplied; the
    # method reads until the blank-line terminator or EOF before building
    # the result, so callers never see a half-read record.
    def parse_record(first_text, first_line, record_number)
      spec = value_spec(first_text, record_number, first_line)
      unless spec[:name].downcase == "dn"
        raise LdifError.new("record must begin with a dn line",
                           record_number, first_line)
      end
      dn = resolve(spec, record_number, first_line)

      controls = []
      changetype = nil
      attributes = nil
      operations = nil
      group = nil
      moddn = nil

      while (logical = next_logical_line)
        text, line = logical
        if text.empty?
          operations << finalize_group(group, record_number, line) if
            changetype == "modify" && !group.nil?
          return build_record(changetype, dn, attributes, operations, moddn,
                              controls, record_number)
        end
        next if text.start_with?("#")

        spec = value_spec(text, record_number, line)
        name = spec[:name].downcase

        if changetype.nil?
          if name == "control"
            controls << parse_control(spec, record_number, line)
            next
          end
          if name == "changetype"
            changetype = spec[:value].downcase
            case changetype
            when "add" then attributes = ordered_attribute_hash
            when "delete"
            when "modify" then operations = []
            when "moddn", "modrdn" then
              changetype = "moddn"
              moddn = {}
            else
              raise LdifError.new("unknown changetype #{spec[:value].inspect}",
                                 record_number, line)
            end
            next
          end
          # Content record without an explicit changetype: treat as add.
          changetype = "add"
          attributes = ordered_attribute_hash
        end

        case changetype
        when "add"
          if spec[:name] == "-"
            raise LdifError.new("'-' separator is only valid in modify records",
                               record_number, line)
          end
          add_attribute_line(attributes, spec, record_number, line)
        when "delete"
          detail = spec[:name] == "-" ? "'-' separator" : "#{name} line"
          raise LdifError.new("delete record may not contain a #{detail}",
                             record_number, line)
        when "modify"
          group = modify_line(spec, name, operations, group,
                              record_number, line)
        when "moddn"
          if spec[:name] == "-"
            raise LdifError.new("'-' separator is only valid in modify records",
                               record_number, line)
          end
          moddn_line(spec, name, moddn, record_number, line)
        end
      end

      if changetype == "modify" && !group.nil?
        operations << finalize_group(group, record_number, @physical_line)
      end
      build_record(changetype, dn, attributes, operations, moddn, controls,
                   record_number)
    end

    def ordered_attribute_hash
      Hash.new { |hash, key| hash[key] = [] }
    end

    def add_attribute_line(attributes, spec, record_number, line)
      value = resolve(spec, record_number, line)
      attributes[spec[:name].downcase.to_sym] << value
    end

    # Drives the modify state machine. +group+ is the [action, attr, values]
    # triple currently being assembled, or nil between groups. A bare "-"
    # line closes the current group; an action line ("add: attr",
    # "delete: attr", "replace: attr") opens the next; any other line adds
    # a value to the open group.
    def modify_line(spec, name, operations, group, record_number, line)
      if spec[:name] == "-"
        unless spec[:encoding] == :plain && spec[:value].empty?
          raise LdifError.new("group separator must be a bare '-' line",
                             record_number, line)
        end
        if group.nil?
          raise LdifError.new("unexpected '-' separator before a modification",
                             record_number, line)
        end
        operations << finalize_group(group, record_number, line)
        return nil
      end

      action = MODIFY_ACTIONS[name]
      if action
        unless spec[:encoding] == :plain
          raise LdifError.new("modify action may not be base64/URL encoded",
                             record_number, line)
        end
        if group
          raise LdifError.new("missing '-' separator between modifications",
                             record_number, line)
        end
        attribute = spec[:value]
        if attribute.empty?
          raise LdifError.new("#{name} line is missing an attribute",
                             record_number, line)
        end
        return [action, attribute.downcase.to_sym, []]
      end

      if group.nil?
        raise LdifError.new("expected add:, delete:, or replace: in modify " \
                           "record, got #{spec[:name]} line",
                           record_number, line)
      end
      unless group[1].to_s == name
        raise LdifError.new("attribute #{name} does not match modification " \
                           "group (#{group[1]})",
                           record_number, line)
      end
      group[2] << resolve(spec, record_number, line)
      group
    end

    def finalize_group(group, record_number, line)
      action, attribute, values = group
      if attribute.nil?
        raise LdifError.new("incomplete modification group",
                           record_number, line)
      end
      values = nil if action == :delete && values.empty?
      [action, attribute, values]
    end

    def moddn_line(spec, name, moddn, record_number, line)
      case name
      when "newrdn", "newsuperior"
        key = name.to_sym
      when "deleteoldrdn"
        key = :delete_old_rdn
      else
        raise LdifError.new("unexpected #{name} line in a moddn record",
                           record_number, line)
      end

      if moddn.key?(key)
        raise LdifError.new("duplicate #{name} line", record_number, line)
      end

      value = resolve(spec, record_number, line)
      value = case value
              when "0" then false
              when "1" then true
              else value
              end if key == :delete_old_rdn
      moddn[key] = value
    end

    def parse_control(spec, record_number, line)
      raw = resolve(spec, record_number, line).to_s
      separator = raw.index(/[ \t]/)
      if separator
        oid = raw[0, separator]
        remainder = raw[(separator + 1)..-1].to_s
      else
        oid = raw
        remainder = String.new
      end
      unless oid =~ /\A[0-9]+(?:\.[0-9]+)*\z/
        raise LdifError.new("malformed control value: #{raw.inspect}",
                           record_number, line)
      end

      criticality = false
      value_part = remainder
      if criticality_token?(remainder, "true")
        criticality = true
        value_part = remainder[4..-1].to_s
      elsif criticality_token?(remainder, "false")
        value_part = remainder[5..-1].to_s
      end
      value_part = value_part[1..-1].to_s if value_part.start_with?(" ")

      value = value_part.empty? ? nil :
                parse_control_value(value_part, record_number, line)
      Control.new(oid, criticality, value)
    end

    def criticality_token?(remainder, token)
      remainder.start_with?(token) &&
        (remainder.length == token.length ||
          remainder[token.length] == " " ||
          remainder[token.length] == ":")
    end

    # control-value is a value-spec (": plain", ":: b64", ":< url").
    def parse_control_value(string, record_number, line)
      if string.start_with?("::")
        decode_base64(strip_marker_space(string[2..-1].to_s),
                      record_number, line)
      elsif string.start_with?(":<")
        resolve_url(strip_marker_space(string[2..-1].to_s),
                    record_number, line)
      elsif string.start_with?(":")
        strip_marker_space(string[1..-1].to_s).dup.
          force_encoding(Encoding::ASCII_8BIT)
      else
        # Tolerate the non-standard but common "control: oid crit value"
        # form emitted by some tools; without a marker the value is plain.
        string.dup.force_encoding(Encoding::ASCII_8BIT)
      end
    end

    def strip_marker_space(string)
      string.start_with?(" ") ? string[1..-1].to_s : string
    end

    def resolve_url(url, record_number, line)
      if @resolver.nil?
        raise LdifError.new("URL value encountered without a resolver: " \
                           "#{url.inspect}", record_number, line)
      end
      @resolver.call(url).to_s.dup.force_encoding(Encoding::ASCII_8BIT)
    end

    # Splits "attrdesc:value", "attrdesc::b64", and "attrdesc:<url".
    def value_spec(text, record_number, line)
      if text == "-"
        return { :name => "-", :encoding => :plain, :value => "" }
      end

      colon = text.index(":")
      if colon.nil? || colon.zero?
        raise LdifError.new("malformed LDIF line: #{text.inspect}",
                           record_number, line)
      end

      name = text[0, colon]
      if name != "-" &&
         name !~ /\A[A-Za-z][A-Za-z0-9-]*(?:;[A-Za-z0-9-]+)*\z/
        raise LdifError.new("invalid attribute description #{name.inspect}",
                           record_number, line)
      end

      marker = text[colon + 1]
      encoding = :plain
      offset = colon + 1
      if marker == ":"
        encoding = :base64
        offset += 1
      elsif marker == "<"
        encoding = :url
        offset += 1
      end
      value = offset < text.length ? text[offset..-1].to_s : ""
      value = value[1..-1].to_s if value.start_with?(" ")
      { :name => name, :encoding => encoding, :value => value }
    end

    def resolve(spec, record_number, line)
      case spec[:encoding]
      when :plain
        spec[:value].dup.force_encoding(Encoding::ASCII_8BIT)
      when :base64
        decode_base64(spec[:value], record_number, line)
      when :url
        resolve_url(spec[:value], record_number, line)
      end
    end

    def decode_base64(value, record_number, line)
      Base64.strict_decode64(value)
    rescue ArgumentError
      raise LdifError.new("invalid base64 value", record_number, line)
    end

    def build_record(changetype, dn, attributes, operations, moddn, controls,
                     record_number)
      case changetype
      when nil, "add"
        AddChange.new(dn, attributes || ordered_attribute_hash, controls)
      when "delete"
        DeleteChange.new(dn, controls)
      when "modify"
        if operations.nil? || operations.empty?
          raise LdifError.new("modify record contains no modifications",
                             record_number, @physical_line)
        end
        ModifyChange.new(dn, operations, controls)
      when "moddn"
        build_moddn(dn, moddn, controls, record_number)
      end
    end

    def build_moddn(dn, moddn, controls, record_number)
      newrdn = moddn[:newrdn]
      delete_old_rdn = moddn[:delete_old_rdn]
      superior = moddn[:newsuperior]
      if newrdn.nil? || !boolean?(delete_old_rdn)
        raise LdifError.new("moddn record requires newrdn and deleteoldrdn",
                           record_number, @physical_line)
      end
      ModifyDNChange.new(dn, newrdn, delete_old_rdn, superior, controls)
    end

    def boolean?(value)
      value == true || value == false
    end
  end

  ##
  # Serializes change records to LDIF. Dangerous values (those beginning
  # with a space, colon, or less-than sign, containing control or non-ASCII
  # bytes, or ending with a space) are emitted as base64 ("::") values,
  # and physical lines longer than #fold_column are folded with a leading
  # space on continuation lines, per RFC 2849.
  class Writer
    # Maximum physical line length (including the folding space).
    DEFAULT_FOLD_COLUMN = 76

    def self.dump(io, changes, fold_column: DEFAULT_FOLD_COLUMN, version: false)
      writer = new(io, fold_column: fold_column, version: version)
      Array(changes).each { |change| writer.write(change) }
      writer.close
      io
    end

    def initialize(io, fold_column: DEFAULT_FOLD_COLUMN, version: false)
      @io = io
      @fold_column = fold_column
      @first = true
      if version
        @io.write("version: #{SPEC_VERSION}\n")
        @io.write("\n")
        @first = false
      end
    end

    # Writes one change record (an AddChange, DeleteChange, ModifyChange,
    # or ModifyDNChange). Records are separated by a blank line.
    def write(change)
      @io.write("\n") unless @first
      @first = false

      dn = change.dn
      emit("dn", dn)
      change.controls.each { |control| emit_control(control) }
      emit("changetype", change.changetype)

      case change
      when AddChange then write_add(change)
      when DeleteChange then nil
      when ModifyChange then write_modify(change)
      when ModifyDNChange then write_moddn(change)
      else
        raise ArgumentError, "cannot serialize #{change.class}"
      end
      @io.write("\n")
      self
    end
    alias_method :<<, :write

    def write_all(changes)
      changes.each { |change| write(change) }
      self
    end

    # Flushes the underlying IO when it supports it.
    def close
      @io.flush if @io.respond_to?(:flush)
      self
    end

    private

    def write_add(change)
      change.attributes.each do |attribute, values|
        Array(values).each { |value| emit(attribute, value) }
      end
    end

    def write_modify(change)
      change.operations.each_with_index do |(action, attribute, values), index|
        @io.write("-\n") unless index.zero?
        emit(action.to_s, attribute.to_s, false)
        Array(values).each { |value| emit(attribute, value) }
      end
    end

    def write_moddn(change)
      emit("newrdn", change.newrdn)
      emit("deleteoldrdn", change.delete_old_rdn ? "1" : "0", false)
      emit("newsuperior", change.new_superior) unless change.new_superior.nil?
    end

    def emit_control(control)
      tail = control.oid.to_s.dup
      tail << " "
      tail << (control.criticality ? "true" : "false")
      unless control.value.nil?
        value = control.value.b
        if unsafe?(value)
          tail << " :: #{encode64(value)}"
        else
          tail << " : #{value}"
        end
      end
      emit("control", tail, false)
    end

    # Emits one "name:value" / "name::b64" line set, folded to the
    # configured column width. +encode_binary+ is false for values that
    # must remain plain LDIF keywords.
    def emit(name, value, encode_binary = true)
      value = value.to_s
      if encode_binary && unsafe?(value)
        write_folded("#{name}:: ", encode64(value))
      else
        write_folded("#{name}: ", value)
      end
    end

    def write_folded(prefix, value)
      value = value.b
      first_width = @fold_column - prefix.bytesize
      if value.empty?
        @io.write(prefix)
        @io.write("\n")
        return
      end

      if first_width <= 0
        @io.write(prefix)
        @io.write("\n")
        write_continuations(value)
        return
      end

      @io.write(prefix)
      @io.write(value.byteslice(0, first_width))
      @io.write("\n")
      write_continuations(value.byteslice(first_width..-1).to_s)
    end

    def write_continuations(remainder)
      continuation_width = @fold_column - 1
      offset = 0
      while offset < remainder.bytesize
        @io.write(" ")
        @io.write(remainder.byteslice(offset, continuation_width))
        @io.write("\n")
        offset += continuation_width
      end
    end

    # RFC 2849 SAFE-CHAR excludes NUL, LF, CR, SPACE at the start/end,
    # ":" and "<" at the start, and any byte above 127.
    def unsafe?(value)
      value = value.b
      return true if value.empty?
      return true if value.getbyte(0) == 32 || value.getbyte(-1) == 32
      return true if value.getbyte(0) == 58 || value.getbyte(0) == 60

      value.each_byte do |byte|
        return true if byte < 32 || byte == 127 || byte > 126
      end
      false
    end

    def encode64(value)
      Base64.strict_encode64(value)
    end
  end

  class << self
    # Streams change records from a filename or IO. When +source+ is a
    # String, the named file is opened and closed; an IO is used directly.
    #
    #   Net::LDAP::LDIF.foreach(io, resolver: ->(url) { ... }) { |c| ... }
    def foreach(source = nil, resolver: nil, block_size: Reader::DEFAULT_BLOCK_SIZE,
                &block)
      raise ArgumentError, "source is required" if source.nil?

      io, owned = open_source(source)
      Reader.foreach(io, resolver: resolver, block_size: block_size, &block)
    ensure
      io.close if owned && io.respond_to?(:close)
    end

    # Reads all change records into an Array. Prefer #foreach for large
    # inputs; this exists for convenience and tests.
    def read(source = nil, resolver: nil, block_size: Reader::DEFAULT_BLOCK_SIZE)
      foreach(source, resolver: resolver, block_size: block_size).to_a
    end

    # Serializes +changes+ to an IO, or to a new StringIO when +io+ is nil.
    def dump(changes, io = nil, fold_column: Writer::DEFAULT_FOLD_COLUMN,
             version: false)
      owned = false
      if io.nil?
        io = StringIO.new(String.new.force_encoding(Encoding::ASCII_8BIT))
        owned = true
      end
      Writer.dump(io, changes, fold_column: fold_column, version: version)
      owned ? io.string : io
    end

    # Returns the LDIF text for +changes+.
    def generate(changes, fold_column: Writer::DEFAULT_FOLD_COLUMN, version: false)
      dump(changes, nil, fold_column: fold_column, version: version)
    end

    private

    def open_source(source)
      case source
      when nil, String then [File.open(source, "rb"), true]
      else [source, false]
      end
    end
  end
end
