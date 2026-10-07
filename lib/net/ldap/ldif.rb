# -*- ruby encoding: utf-8 -*-
require 'base64'

##
# Streaming reader and writer for LDAP change records (RFC 2849).
#
# Unlike Net::LDAP::Dataset, this module understands the four LDIF change
# operations (add, delete, modify and moddn/modrdn), including ordered
# modify groups separated by "-" lines and record-level controls. Input is
# consumed incrementally from any IO-like object, so arbitrarily large LDIF
# files never have to be held in memory. A change record is only yielded
# once its terminating blank line has been read, so a record can never be
# executed before it is complete.
#
# URL-referenced values (attr:< URL) are never fetched implicitly. They are
# resolved only through an explicitly supplied callable, :url_resolver.
class Net::LDAP::LDIF
  include Enumerable

  # Maximum physical line length in bytes (excluding the line separator).
  # RFC 2849 recommends folding at 78 bytes.
  MAX_LINE = 78

  # LDIF modify keywords mapped to LDAP modification operation symbols.
  MODIFY_OPERATIONS = {
    "add" => :add,
    "delete" => :delete,
    "replace" => :replace,
  }.freeze

  # LDIF changetype keywords mapped to normalized action symbols.
  CHANGE_TYPES = {
    "add" => :add,
    "delete" => :delete,
    "modify" => :modify,
    "modrdn" => :moddn,
    "moddn" => :moddn,
  }.freeze

  # Attribute-description characters permitted by RFC 2849 keystring /
  # RFC 4512 attributeType: letters, digits, digits and hyphens.
  ATTRIBUTE_NAME = /[A-Za-z][A-Za-z0-9-]*/.freeze

  class << self
    # Parses a control line into [oid, criticality, encoding, value].
    # +criticality+ is a boolean (default false); +encoding+ is :base64 or
    # :url (nil for a value-less control); +value+ is the still-encoded
    # value String. RFC 2849 uses a single delimiter character for the
    # criticality ("control: OID true") and two for a base64 value
    # ("control: OID true:: value"); both are accepted.
    def parse_control_line(line)
      body = line.sub(/\Acontrol:\s?/i, "")
      oid, remainder = split_token(body)
      return [nil, false, nil, nil] unless valid_oid?(oid)
      criticality = false
      encoding = nil
      value = nil

      unless remainder.nil? || remainder.empty?
        token, after_token = split_token(remainder)
        critical_token, delimiter = split_criticality(token)
        if critical_token =~ /\A(?:true|false)\z/i &&
           (delimiter.nil? || after_token)
          criticality = critical_token.downcase == "true"
          if delimiter
            encoding = delimiter.start_with?(":") ? :base64 : :url
            value = after_token.nil? ? "" : strip_fill(after_token)
          end
        else
          # Tolerate "control: OID::<value>" (criticality omitted).
          encoding, value = value_from(remainder)
        end
      end

      [oid, criticality, encoding, value]
    end

    def valid_oid?(oid)
      oid =~ /\A[0-9]+(?:\.[0-9]+)+\z/
    end

    # Splits off the first whitespace-delimited token, e.g. "true::" and the
    # remainder. Unlike String#split, the remainder (everything after the
    # first run of spaces) is preserved verbatim.
    def split_token(string)
      head, separator, tail = string.partition(/[ \t]+/)
      separator.empty? ? [head, nil] : [head, tail]
    end

    # Separates the criticality boolean from an attached value delimiter,
    # returning e.g. ["true", ":"] for "true::". Per RFC 2849 the
    # criticality is followed by FILL then the value-spec marker ("::" or
    # ":<"); some tools omit the space and glue them as "true::".
    def split_criticality(token)
      match = token.match(/\A(true|false)(::|:<|<)?\z/i)
      match ? [match[1], match[2]] : [token, nil]
    end

    def value_from(remainder)
      return [nil, nil] if remainder.nil? || remainder.empty?

      if remainder.start_with?("::")
        [:base64, strip_fill(remainder[2..])]
      elsif remainder.start_with?(":")
        [:plain, strip_fill(remainder[1..])]
      elsif remainder.start_with?("<")
        [:url, strip_fill(remainder[1..])]
      end
    end

    def parse_spec(line, line_number, record_number)
      colon = line.index(":")
      if colon.nil?
        raise ParseError.new("malformed LDIF line (missing colon)", record_number, line_number)
      end

      name = line.byteslice(0, colon)
      unless name =~ /\A#{ATTRIBUTE_NAME.source}\z/o
        raise ParseError.new("invalid attribute name #{name.inspect}", record_number, line_number)
      end

      rest = line.byteslice(colon + 1, line.bytesize) || ""
      encoding, remainder =
        if rest.start_with?(":")
          [:base64, rest.byteslice(1, rest.bytesize)]
        elsif rest.start_with?("<")
          [:url, rest.byteslice(1, rest.bytesize)]
        else
          [:plain, rest]
        end

      value = strip_fill(remainder || "")
      [name, encoding, value]
    end

    # Consumes the single optional FILL SPACE (RFC 2849) after the value-spec
    # delimiter. Only one leading space is removed; any following spaces are
    # part of the value. Trailing spaces are retained because they are
    # significant (they force base64 encoding on output).
    def strip_fill(value)
      value.start_with?(" ") ? value.byteslice(1, value.bytesize) : value
    end

    # Streams change records from +io+ and yields them to the given block.
    # See Reader.new for the supported options. Without a block, returns an
    # Enumerator.
    def read(io, **options, &block)
      Reader.new(io, **options).each(&block)
    end
    alias_method :parse, :read

    # Streams change records from +io+ and applies each one to +ldap+ (an
    # object responding to #add, #delete, #modify and #rename, such as a
    # Net::LDAP instance). Nothing is executed until the complete record has
    # been read. Returns an Array of the ldap call return values.
    def apply(io, ldap, **options)
      results = []
      Reader.new(io, **options).each do |record|
        results << apply_record(record, ldap)
      end
      results
    end

    # Serializes +records+ (any Enumerable of change-record Hashes) to +io+.
    # See Writer.new for the supported options. Returns +io+.
    def write(io, records, **options)
      writer = Writer.new(io, **options)
      records.each { |record| writer << record }
      io
    end
    alias_method :dump, :write

    # Translates one parsed change record into the matching call on +ldap+.
    # Record-level controls are forwarded where the protocol supports them.
    def apply_record(record, ldap)
      action = record[:action]
      ber_controls = encode_ber_controls(record[:controls])
      raw_controls = encode_raw_controls(record[:controls])

      case action
      when :add
        args = { :dn => record[:dn], :attributes => record[:attributes] }
        args[:controls] = ber_controls unless ber_controls.empty?
        ldap.add(args)
      when :delete
        args = { :dn => record[:dn] }
        args[:control_codes] = raw_controls unless raw_controls.empty?
        ldap.delete(args)
      when :modify
        operations = record[:operations].map do |operation, attribute, values|
          # An empty value list, or a list containing only empty strings,
          # is LDIF's way of deleting/replacing the whole attribute. net-ldap
          # represents that with a nil value.
          meaningful = Array(values).reject(&:empty?)
          mapped = meaningful.empty? ? nil : values
          [operation, attribute, mapped]
        end
        args = { :dn => record[:dn], :operations => operations }
        args[:controls] = ber_controls unless ber_controls.empty?
        ldap.modify(args)
      when :moddn
        args = {
          :olddn => record[:dn],
          :newrdn => record[:newrdn],
          :delete_attributes => record[:delete_old_rdn],
          :new_superior => record[:new_superior],
        }
        args[:controls] = ber_controls unless ber_controls.empty?
        ldap.rename(args)
      else
        raise ArgumentError, "unsupported LDIF action #{action.inspect}"
      end
    end

    # add/modify/rename expect an Array of already BER-encoded control
    # sequences (see Connection#add / #modify).
    def encode_ber_controls(controls)
      Array(controls).map do |control|
        oid, criticality, value = control_parts(control)
        [oid.to_ber, (criticality ? true : false).to_ber, value && value.to_ber_bin]
          .reject(&:nil?)
          .to_ber_sequence
      end
    end

    # delete expects raw triples passed through Array#to_ber_control.
    def encode_raw_controls(controls)
      Array(controls).map do |control|
        oid, criticality, value = control_parts(control)
        [oid, criticality ? true : false, value]
      end
    end

    def control_parts(control)
      if control.is_a?(Hash)
        [control[:oid], control[:criticality], control[:value]]
      else
        [control[0], control[1], control[2]]
      end
    end
  end

  # :call-seq:
  #   LDIF.new(io, mode = "r", url_resolver: nil, block_size: 4096,
  #           newline: "\n", moddn_keyword: "modrdn")
  #
  # In read mode (+"r"+, the default) returns a streaming Reader. In write
  # mode (+"w"+) returns a streaming Writer.
  def initialize(io, mode = "r", **options)
    @implementation =
      if mode.to_s == "w"
        Writer.new(io, **options.slice(:newline, :moddn_keyword))
      else
        Reader.new(io, **options.slice(:url_resolver, :block_size))
      end
  end

  # Reader: delegates to Reader#each. Writer: not supported.
  def each(&block)
    unless @implementation.is_a?(Reader)
      raise ArgumentError, "LDIF opened in write mode does not support #each"
    end
    @implementation.each(&block)
  end

  # Reader: returns the next change record. Writer: not supported.
  def next_record
    @implementation.next_record
  end

  # Writer: serializes one record. Reader: not supported.
  def <<(record)
    @implementation << record
  end
  alias_method :change, :<<

  # Applies each streamed record to +ldap+ (read mode only).
  def apply(ldap)
    results = []
    each do |record|
      results << self.class.apply_record(record, ldap)
    end
    results
  end

  ##
  # Raised when LDIF input cannot be parsed. #record and #line identify the
  # 1-based change-record number and physical line at which the problem was
  # detected.
  class ParseError < Net::LDAP::Error
    attr_reader :record
    attr_reader :line

    def initialize(message, record, line)
      @record = record
      @line = line
      super("LDIF parse error at record #{record}, line #{line}: #{message}")
    end
  end

  # Reads an arbitrary IO object in fixed-size chunks and returns physical
  # lines (without separators) together with 1-based line numbers. Reading
  # in chunks keeps peak memory usage low regardless of how the caller's IO
  # is itself buffered.
  class ChunkReader
    def initialize(io, block_size)
      @io = io
      @block_size = block_size
      @buffer = "".b
      @line_number = 0
      @eof = false
    end

    # Returns [line, line_number] or nil at end of input.
    def gets
      loop do
        index = separator_index(@buffer)
        index = nil if dangling_carriage_return?(index)

        if index
          return consume(index)
        elsif @eof
          return nil if @buffer.empty?

          line = @buffer
          @buffer = "".b
          @line_number += 1
          return [line, @line_number]
        end

        fill_buffer
      end
    end

    private

    def separator_index(buffer)
      buffer.index(/\r\n?|\n/)
    end

    # A trailing CR might be the first half of a CRLF pair split across two
    # read chunks; wait for the next byte before treating it as a separator.
    def dangling_carriage_return?(index)
      index == @buffer.bytesize - 1 && @buffer.getbyte(index) == 0x0D && !@eof
    end

    def consume(index)
      separator = @buffer[index..].match(/\r\n?|\n/)[0]
      line = @buffer.byteslice(0, index)
      consumed = index + separator.bytesize
      @buffer = @buffer.byteslice(consumed, @buffer.bytesize) || "".b
      @line_number += 1
      [line, @line_number]
    end

    def fill_buffer
      return if @eof

      chunk = @io.read(@block_size)
      if chunk.nil? || chunk.empty?
        @eof = true
      else
        @buffer << chunk.b
      end
    end
  end

  # Streams change records out of LDIF input. It folds continuation lines,
  # and only hands a fully terminated record to its caller.
  class Reader
    include Enumerable

    # :call-seq:
    #   Reader.new(io, url_resolver: nil, block_size: 4096)
    #
    # +io+ must respond to #read(length). +url_resolver+ is an optional
    # callable receiving a URL String and returning the resolved value as a
    # (binary) String. When it is nil, any URL-referenced value raises a
    # ParseError; neither local files nor the network are ever accessed
    # implicitly. +block_size+ is the number of bytes read from +io+ at a
    # time, which makes it possible to parse files delivered in arbitrarily
    # small IO chunks.
    def initialize(io, url_resolver: nil, block_size: 4096)
      @lines = ChunkReader.new(io, block_size)
      @url_resolver = url_resolver
      @record_count = 0
      @unread = nil
      @seen_record = false
    end

    # Yields each completed change record as a Hash. Returns an Enumerator
    # when no block is given.
    def each
      return to_enum(:each) unless block_given?

      while (record = next_record)
        yield record
      end
    end

    # Returns the next change record Hash, or nil at end of input.
    def next_record
      logical = next_logical
      return nil unless logical

      text, start_line, = logical

      # Skip blank lines and comments. A version: header is only permitted
      # before the first record.
      while text.empty? || text.start_with?("#") ||
            (!@seen_record && version_line?(text))
        logical = next_logical
        return nil unless logical

        text, start_line, = logical
      end

      spec = Net::LDAP::LDIF.parse_spec(text, start_line, 0)
      unless spec && spec[0].downcase == "dn"
        raise_error("expected the start of a record (dn:)", 0, start_line)
      end

      _, encoding, value = spec
      @seen_record = true
      state = RecordState.new(value, encoding, start_line, self)

      while (logical = next_logical)
        line, line_number, = logical
        state.process(line, line_number)
        return state.build! if state.complete?
      end

      # A record terminated by EOF without a final blank line is permitted by
      # RFC 2849, but it is only emitted after the whole record was read.
      state.build!
    end

    def next_record_number
      @record_count += 1
    end

    def url_resolver
      @url_resolver
    end

    def raise_error(message, record_number, line_number)
      raise ParseError.new(message, record_number, line_number)
    end

    private

    def version_line?(text)
      text =~ /\Aversion:[ \t]*[0-9]+[ \t]*\z/i
    end

    # Returns [logical_line, start_line_number, end_line_number], joining
    # physical lines that begin with exactly one SPACE (RFC 2849 folding).
    # A leading TAB is deliberately not treated as a continuation.
    def next_logical
      physical = next_physical
      return nil unless physical

      line, start_number = physical
      end_number = start_number

      while (peek = next_physical)
        next_line, next_number = peek
        if continuation?(next_line)
          # The single leading SPACE is the fold marker and is removed when
          # reassembling the logical line. Any further leading spaces are
          # content.
          line = "#{line}#{next_line.byteslice(1, next_line.bytesize)}"
          end_number = next_number
        else
          @unread = peek
          break
        end
      end

      [line, start_number, end_number]
    end

    # When next_logical over-reads the first physical line of the next
    # logical line it is stashed here.
    def next_physical
      unread = @unread
      @unread = nil
      unread || @lines.gets
    end

    # RFC 2849 folding is signalled by a single leading SPACE, which is
    # consumed when the logical line is reassembled. Additional leading
    # spaces are part of the value. A leading TAB is deliberately not a
    # continuation marker.
    def continuation?(line)
      line.getbyte(0) == 0x20
    end
  end

  # Accumulates a single change record while it is being read. It resolves
  # folded lines and defers all URL fetching and validation until the blank
  # line that terminates the record has been consumed.
  class PendingUrl < String
    attr_reader :url
    attr_reader :line_number
    attr_reader :location

    def initialize(url, line_number, location)
      @url = url
      @line_number = line_number
      @location = location
      super("")
    end

    def resolve(resolver, state)
      if resolver.nil?
        state.fail_parse!("URL-referenced value for #{@location.join(' ')} " \
                         "requires an explicit url_resolver (no implicit " \
                         "file or network access)", @line_number)
      end
      begin
        replace(resolver.call(@url).to_s.b)
      rescue ParseError
        raise
      rescue => e
        state.fail_parse!("url_resolver failed for #{@location.join(' ')}: " \
                         "#{e.message}", @line_number)
      end
    end
  end

  class RecordState
    attr_reader :number

    def initialize(dn, dn_encoding, dn_line, reader)
      @reader = reader
      @number = reader.next_record_number
      @dn = dn
      @dn_encoding = dn_encoding
      @start_line = dn_line
      @last_line = dn_line
      @action = nil
      @controls = []
      @attributes = []
      @groups = []
      @current_group = nil
      @newrdn = nil
      @new_superior = nil
      @delete_old_rdn = nil
      @pending_urls = []
      @content_started = false
      @complete = false
    end

    def complete?
      @complete
    end

    # Feeds one logical line (+text+) that begins on physical line +number+.
    def process(text, number)
      @last_line = number

      if text.empty?
        @complete = true
        return
      end
      return if text.start_with?("#")

      # The single "-" separator terminates a modify group (RFC 2849). It is
      # not an attribute specification, so it is handled before the colon is
      # required.
      if text == "-"
        handle_separator(number)
        return
      end

      spec = Net::LDAP::LDIF.parse_spec(text, number, @number)
      name, encoding, value = spec
      keyword = name.downcase

      if keyword == "control"
        handle_control(text, number)
      elsif keyword == "changetype"
        handle_changetype(value, number)
      elsif @action.nil?
        # Content record: no changetype, treat it as an add.
        @content_started = true
        @action = :add
        add_value(keyword, name, encoding, value, number)
      else
        @content_started = true
        dispatch(keyword, name, encoding, value, number)
      end
    end

    # Validates the record and resolves pending URLs. Called only after the
    # terminating blank line (or EOF) has been read.
    def build!
      finish_modify

      case @action
      when nil
        error!("record has no changetype and no attributes", @last_line)
      when :add
        resolve_pending_urls!
        build_add
      when :delete
        resolve_pending_urls!
        build_delete
      when :modify
        resolve_pending_urls!
        build_modify
      when :moddn
        resolve_pending_urls!
        build_moddn
      end
    end

    private

    def handle_control(text, number)
      if @content_started
        error!("control lines must precede record content", number)
      end
      if @action == :modify || @action == :moddn
        error!("control lines are not valid inside modify/moddn content", number)
      end
      @controls << parse_control(text, number)
    end

    def handle_changetype(value, number)
      unless @action.nil?
        error!("duplicate changetype", number)
      end
      unless (action = CHANGE_TYPES[value.downcase])
        error!(%(unsupported changetype "#{value}"), number)
      end
      @action = action
    end

    def dispatch(keyword, name, encoding, value, number)
      case @action
      when :add
        add_value(keyword, name, encoding, value, number)
      when :delete
        error!(%(unexpected attribute "#{name}" in a delete record), number)
      when :moddn
        handle_moddn_line(keyword, encoding, value, number)
      when :modify
        handle_modify_line(keyword, name, encoding, value, number)
      end
    end

    def add_value(keyword, name, encoding, value, number)
      @attributes << [name, decode_value(encoding, value, number, ["attribute", name])]
    end

    def handle_moddn_line(keyword, encoding, value, number)
      case keyword
      when "newrdn"
        error!("duplicate newrdn", number) unless @newrdn.nil?
        @newrdn = decode_value(encoding, value, number, %w[newrdn])
      when "newsuperior"
        error!("duplicate newsuperior", number) unless @new_superior.nil?
        @new_superior = decode_value(encoding, value, number, %w[newsuperior])
      when "deleteoldrdn"
        normalized = value.strip.downcase
        unless %w[0 1].include?(normalized)
          error!("deleteoldrdn must be 0 or 1", number)
        end
        @delete_old_rdn = normalized == "1"
      else
        error!(%(unexpected attribute "#{keyword}" in a moddn record), number)
      end
    end

    def handle_modify_line(keyword, name, encoding, value, number)
      if (operation = MODIFY_OPERATIONS[keyword])
        finish_group
        attribute = decode_value(encoding, value, number, %w[modification])
        @current_group = { :operation => operation, :attribute => attribute, :values => [] }
      else
        if @current_group.nil?
          error!("expected add:, delete:, replace:, or a \"-\" separator", number)
          return
        end
        decoded = decode_value(encoding, value, number, ["modification", keyword])
        @current_group[:values] << decoded
      end
    end

    def handle_separator(number)
      unless @action == :modify
        error!("\"-\" separator is only valid inside a modify record", number)
      end
      if @current_group.nil?
        error!("unexpected \"-\" before any modification", number)
      end
      finish_group
    end

    def finish_group
      return if @current_group.nil?
      @groups << @current_group
      @current_group = nil
    end

    def finish_modify
      finish_group if @action == :modify
    end

    def build_add
      attributes = {}
      @attributes.each do |name, value|
        (attributes[name] ||= []) << value
      end
      record(:add, :attributes => attributes)
    end

    def build_delete
      record(:delete)
    end

    def build_modify
      error!("modify record contains no modifications", @last_line) if @groups.empty?
      operations = @groups.map do |group|
        [group[:operation], group[:attribute], group[:values]]
      end
      record(:modify, :operations => operations)
    end

    def build_moddn
      error!("moddn record is missing newrdn", @last_line) if @newrdn.nil?
      record(:moddn,
             :newrdn => @newrdn,
             :new_superior => @new_superior,
             :delete_old_rdn => @delete_old_rdn || false)
    end

    def record(action, extras = {})
      resolved_dn = decode_value(@dn_encoding, @dn, @start_line, %w[dn])
      if resolved_dn.nil? || resolved_dn.empty?
        error!("record is missing a dn", @start_line)
      end
      {
        :action => action,
        :dn => resolved_dn,
        :controls => @controls,
      }.merge(extras)
    end

    def decode_value(encoding, value, line_number, location)
      case encoding
      when :plain
        value.dup.force_encoding(Encoding::UTF_8)
      when :base64
        decode_base64(value, line_number, location)
      when :url
        pending = PendingUrl.new(value, line_number, location)
        @pending_urls << pending
        pending
      end
    end

    # Fetches every deferred URL value. Called only from #build!, after the
    # terminating blank line has been consumed and the record validated.
    def resolve_pending_urls!
      @pending_urls.each do |pending|
        pending.resolve(@reader.url_resolver, self)
      end
    end

    def decode_base64(value, line_number, location)
      begin
        Base64.strict_decode64(value.delete(" \t"))
      rescue ArgumentError
        error!("invalid base64 value for #{location.join(' ')}", line_number)
      end
    end

    def parse_control(text, number)
      oid, criticality, encoding, raw_value =
        Net::LDAP::LDIF.parse_control_line(text)
      error!("malformed control line", number) if oid.nil?

      value = encoding ? decode_value(encoding, raw_value, number, %w[control]) : nil
      { :oid => oid, :criticality => criticality, :value => value }
    end

    def error!(message, line_number)
      @reader.raise_error(message, @number, line_number)
    end

    # Public hook used by PendingUrl so deferred URL failures are reported
    # against this record's number and line.
    def fail_parse!(message, line_number)
      error!(message, line_number)
    end
    public :fail_parse!
  end

  # Serializes change records to LDIF. Values that are unsafe to emit as
  # plain text are base64-encoded and every physical line is folded to
  # MAX_LINE bytes. Records are written immediately, so the writer also
  # streams and never accumulates the whole document.
  class Writer
    # :call-seq:
    #   Writer.new(io, newline: "\n", moddn_keyword: "modrdn")
    def initialize(io, newline: "\n", moddn_keyword: "modrdn")
      @io = io
      @newline = newline
      @moddn_keyword = moddn_keyword
    end

    # Serializes one change record Hash (the same shape produced by Reader)
    # and returns self so calls can be chained.
    def <<(record)
      change(record)
      self
    end
    alias_method :write, :<<

    def change(record)
      action = normalize_action(record[:action])
      dn = record[:dn]

      emit_spec("dn", dn)
      emit_controls(record[:controls])

      case action
      when :add then write_add(record)
      when :delete then write_delete(record)
      when :modify then write_modify(record)
      when :moddn then write_moddn(record)
      else raise ArgumentError, "unsupported LDIF action #{record[:action].inspect}"
      end

      emit("")
    end

    private

    def normalize_action(action)
      case action.to_s.downcase
      when "add" then :add
      when "delete" then :delete
      when "modify" then :modify
      when "moddn", "modrdn" then :moddn
      else raise ArgumentError, "unsupported LDIF action #{action.inspect}"
      end
    end

    def write_add(record)
      emit_line("changetype: add")
      each_attribute(record[:attributes]) do |name, value|
        emit_spec(name, value)
      end
    end

    def write_delete(_record)
      emit_line("changetype: delete")
    end

    def write_modify(record)
      emit_line("changetype: modify")
      groups = normalize_operations(record[:operations] || [])
      groups.each_with_index do |group, index|
        operation, attribute, values = group
        emit_modification_header(operation, attribute)
        Array(values).each do |value|
          # A nil value means "modify the whole attribute" (no value lines
          # are emitted); an explicit empty String emits "attribute:".
          emit_spec(attribute, value) unless value.nil?
        end
        emit_line("-") unless index == groups.size - 1
      end
    end

    # Emits the "add:/delete:/replace: <attribute>" line, base64-encoding the
    # attribute description when it contains unsafe characters (RFC 2849
    # allows the value portion of the modification line to be base64).
    def emit_modification_header(operation, attribute)
      if encode_base64?(attribute)
        emit_line("#{operation}:: #{encode_base64(attribute)}")
      else
        emit_line("#{operation}: #{attribute}")
      end
    end

    # Accepts three-element operation triples ([:add, :mail, "value"]), the
    # Reader's Hash groups, or two-element triples where the attribute is
    # taken from the Hash form.
    def normalize_operations(operations)
      operations.map do |operation|
        if operation.is_a?(Hash)
          [operation[:operation], operation[:attribute] || operation[:name], operation[:values]]
        else
          [operation[0], operation[1], operation[2]]
        end
      end
    end

    def write_moddn(record)
      emit_line("changetype: #{@moddn_keyword}")
      emit_spec("newrdn", record[:newrdn])
      delete_old = record[:delete_old_rdn]
      emit_line("deleteoldrdn: #{delete_old ? 1 : 0}") unless delete_old.nil?
      emit_spec("newsuperior", record[:new_superior]) unless record[:new_superior].nil?
    end

    def each_attribute(attributes)
      return if attributes.nil?
      if attributes.is_a?(Hash)
        attributes.each do |name, values|
          Array(values).each { |value| yield name.to_s, value }
        end
      else
        Array(attributes).each { |pair| yield pair[0].to_s, pair[1] }
      end
    end

    def emit_controls(controls)
      Array(controls).each do |control|
        emit_control(control)
      end
    end

    def emit_control(control)
      if control.is_a?(Hash)
        oid = control[:oid]
        criticality = control[:criticality]
        value = control[:value]
      else
        oid, criticality, value = control
      end

      line = "control: #{oid}"
      unless criticality.nil? && value.nil?
        line << " #{criticality ? 'true' : 'false'}"
      end
      if value
        encoded = encode_base64(value)
        line << ":: #{encoded}"
      end
      emit_line(line)
    end

    # Emits a single attribute/value specification line, choosing base64 or
    # plain encoding and folding the physical line as required.
    def emit_spec(name, value)
      value = "" if value.nil?
      if encode_base64?(value)
        emit_line("#{name}:: #{encode_base64(value)}")
      elsif value.empty?
        emit_line("#{name}:")
      else
        emit_line("#{name}: #{value}")
      end
    end

    def emit_line(content)
      fold(content).each { |physical| emit(physical) }
    end

    def emit(line)
      @io.write(line)
      @io.write(@newline)
    end

    # Splits a (possibly already base64-encoded) logical line into physical
    # lines no longer than MAX_LINE bytes, prefixing continuation lines with
    # a single space. Plain UTF-8 lines are folded on character boundaries so
    # a multi-byte character is never split; base64 lines are split on raw
    # bytes because their content is ASCII by construction.
    def fold(content)
      return [""] if content.empty?

      string = content.to_s
      binary = !string.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      binary ? fold_bytes(string.b) : fold_characters(string)
    end

    def fold_bytes(bytes)
      lines = [take_bytes!(bytes, MAX_LINE)]
      lines << " #{take_bytes!(bytes, MAX_LINE - 1)}" until bytes.empty?
      lines
    end

    def fold_characters(string)
      lines = [take_characters!(string, MAX_LINE)]
      lines << " #{take_characters!(string, MAX_LINE - 1)}" until string.empty?
      lines
    end

    def take_bytes!(bytes, size)
      piece = bytes.byteslice(0, size)
      bytes.slice!(0, size)
      piece
    end

    # Removes whole UTF-8 characters up to +size+ bytes, never splitting a
    # character across two physical lines.
    def take_characters!(string, size)
      taken = ""
      taken_bytes = 0
      remaining = string
      until remaining.empty?
        char = remaining[0]
        char_bytes = char.bytesize
        break if taken_bytes + char_bytes > size

        taken << char
        taken_bytes += char_bytes
        remaining = remaining.byteslice(char_bytes, remaining.bytesize)
      end
      string.replace(remaining)
      taken
    end

    def encode_base64(value)
      Base64.strict_encode64(value.to_s.b)
    end

    # RFC 2849 "unsafe" values must be base64-encoded: values that begin with
    # ':' or '<' or a space, end with a space, contain NUL/control chars or
    # bytes that are not valid UTF-8.
    def encode_base64?(value)
      string = value.to_s
      bytes = string.b
      return false if bytes.empty?

      bytes.start_with?(":", "<", " ") ||
        bytes.end_with?(" ") ||
        !string.dup.force_encoding(Encoding::UTF_8).valid_encoding? ||
        string.each_codepoint.any? { |cp| cp < 0x20 || cp == 0x7f }
    end
  end
end
