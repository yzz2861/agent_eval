# frozen_string_literal: true

module Net; module SFTP; module Operations

  # Exception raised when a single remote entry name cannot be represented
  # on the local file system under the configured policy.
  class InvalidNameError < Net::SFTP::Exception
    # The offending remote name, as raw (ASCII-8BIT) bytes.
    attr_reader :name

    def initialize(message, name)
      @name = name
      super(message)
    end
  end

  # Exception raised when two distinct remote entry names would resolve to
  # the same local name under the configured name-equivalence function, or
  # when an entry collides with the mapping manifest itself.
  class NameCollisionError < Net::SFTP::Exception
    # The local (mapped) name that more than one remote name resolves to.
    attr_reader :local_name

    def initialize(message, local_name)
      @local_name = local_name
      super(message)
    end
  end

  # Maps remote directory entry names to names that are safe to persist on
  # a local file system. Remote names are treated as opaque sequences of
  # bytes (the SFTP protocol does not impose an encoding); the original raw
  # bytes are always preserved as the identity of an entry, both in the
  # collision analysis and in the reverse-lookup manifest.
  #
  # Two mapping strategies are supported:
  #
  # * <tt>:reject</tt> - any name that is not valid UTF-8, or that contains
  #   a path separator, a control character, a parent-directory segment, or
  #   a platform reserved name, causes the whole directory layer to be
  #   rejected before anything is written to disk.
  # * <tt>:escape</tt> - problematic bytes are percent-encoded (e.g. an
  #   invalid byte 0xFF becomes "%FF"). The escaping is unambiguous and
  #   fully reversible; notably it never relies on encoding replacement
  #   characters, so two different invalid byte sequences can never collapse
  #   onto the same local name.
  #
  # Collision detection is performed on the *mapped* names, compared through
  #   an injectable equivalence function. This makes it possible to emulate
  #   file systems that fold case (NTFS, HFS+) or apply Unicode
  #   normalization (HFS+) without relying on the behavior of the host that
  #   happens to run the client.
  class NameMapper

    # The strategy in effect (<tt>:reject</tt> or <tt>:escape</tt>).
    attr_reader :strategy

    # The callable used to derive the collision key for a mapped name.
    attr_reader :equivalency

    # The callable used to recognize platform reserved device names.
    attr_reader :reserved_names

    # The basename of the reverse-lookup manifest, or nil if disabled.
    attr_reader :manifest_name

    # Windows reserved device stems (CON, PRN, AUX, NUL, COM1..9,
    # LPT1..9), recognized case-insensitively regardless of extension.
    WINDOWS_RESERVED = /\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\z/i

    # ASCII bytes that are always legal to leave unescaped in a mapped
    # name: letters, digits and a conservative set of punctuation. Every
    # other byte (including "%", separators, control bytes and trailing
    # spaces/dots) is percent encoded when escaping.
    SAFE_ASCII = (("A".."Z").to_a + ("a".."z").to_a + ("0".."9").to_a +
                 %w[- _ ~ ! @ ^ & + = , ;]).freeze

    # ASCII bytes that are allowed unescaped at any position (space and
    # dot are additionally allowed except as the final byte).
    SAFE_ASCII_INTERNAL = (SAFE_ASCII + [" ", "."]).freeze

    # The default equivalence function: byte/string identity, emulating a
    # case-sensitive POSIX file system that does not normalize Unicode.
    IDENTITY = ->(name) { name }

    # Emulates a case-folding file system (e.g. NTFS, default HFS+): the
    # collision key is the Unicode case-folded form of the name.
    CASE_FOLD = ->(name) { name.downcase(:fold) }

    # Emulates a file system that applies Unicode normalization (e.g. HFS+
    # NFD): the collision key is the NFD form of the name.
    UNICODE_NFD = ->(name) { name.unicode_normalize(:nfd) }

    # Emulates a case-folding file system that also applies NFD
    # normalization.
    CASE_FOLD_NFD = ->(name) { name.unicode_normalize(:nfd).downcase(:fold) }

    # Builds a new mapper. Options:
    #
    # * <tt>:strategy</tt> - <tt>:reject</tt> (the default) or
    #   <tt>:escape</tt>.
    # * <tt>:equivalency</tt> - a callable that receives a mapped name (a
    #   valid UTF-8 String) and returns its collision key. Defaults to
    #   identity. Any of the presets on this class (CASE_FOLD, UNICODE_NFD,
    #   ...) can be used.
    # * <tt>:reserved_names</tt> - a callable that receives a mapped name
    #   and returns truthy when the name is a platform reserved device name.
    #   Pass nil to disable the check. Defaults to the Windows reserved
    #   device list (a conservative, platform independent default).
    # * <tt>:manifest_name</tt> - basename of the reverse-lookup manifest.
    #   The name itself participates in collision checking for the top-level
    #   directory. Defaults to NameMapper::DEFAULT_MANIFEST_NAME; pass nil or
    #   false to suppress the manifest entirely.
    def initialize(options = {})
      @strategy = options[:strategy] || :reject
      unless [:reject, :escape].include?(@strategy)
        raise ArgumentError, "unknown name mapping strategy #{@strategy.inspect}"
      end

      @equivalency = options[:equivalency] || IDENTITY
      unless @equivalency.respond_to?(:call)
        raise ArgumentError, ":equivalency must respond to #call"
      end

      @reserved_names = options.key?(:reserved_names) ? options[:reserved_names] : default_reserved
      unless @reserved_names.nil? || @reserved_names.respond_to?(:call)
        raise ArgumentError, ":reserved_names must respond to #call or be nil"
      end

      if options.key?(:manifest_name)
        value = options[:manifest_name]
        @manifest_name = (value.nil? || value == false) ? nil : String(value)
      else
        @manifest_name = DEFAULT_MANIFEST_NAME
      end

      if @manifest_name
        validate_manifest_name!
      end
    end

    # Maps every entry name in a single remote directory layer at once.
    # +names+ is an array of raw remote names (any encoding; they are duped
    # as ASCII-8BIT). +top_level+ must be true for the destination root, so
    # that the manifest name is included in the collision check.
    #
    # Returns an array of [raw_name, mapped_name] pairs, in input order.
    # Raises InvalidNameError or NameCollisionError before returning when
    # the layer cannot be represented locally; in that case no entry has
    # been written and the caller must abort the layer.
    def map(names, top_level = false)
      pairs = names.map do |raw|
        bytes = String(raw).dup.force_encoding(Encoding::ASCII_8BIT)
        [bytes, map_one(bytes)]
      end

      seen = {}
      pairs.each do |_raw, mapped|
        register!(seen, mapped, mapped)
      end

      if top_level && manifest_name
        # The manifest is written by the client itself; it must not be
        # shadowed by, nor shadow, any real remote entry.
        register!(seen, manifest_name, manifest_name)
      end

      pairs
    end

    # Percent-encodes a single raw remote name. Never replaces invalid
    # bytes with a substitution character; invalid or unsafe bytes are each
    # encoded individually so the transformation is injective (and thus
    # reversible without ambiguity). Valid printable UTF-8 characters are
    # left untouched; invalid bytes and any unsafe code point (controls,
    # separators, "%", non-printable characters, trailing space/dot) are
    # percent encoded byte for byte.
    def self.escape(bytes)
      data = String(bytes).dup.force_encoding(Encoding::ASCII_8BIT)
      out = String.new.force_encoding(Encoding::UTF_8)
      index = 0
      while index < data.bytesize
        byte = data.getbyte(index)
        length = utf8_sequence_length(data, index)
        if length > 1
          run = data.byteslice(index, length).force_encoding(Encoding::UTF_8)
          character = run.valid_encoding? && run.each_char.to_a
          last_here = index + length >= data.bytesize
          if character && character.length == 1 && safe_unicode?(character.first, last_here)
            out << run
            index += length
          else
            # Malformed lead/truncated sequence: encode the lead byte on
            # its own and re-scan the continuation bytes.
            out << encode_byte(byte)
            index += 1
          end
        else
          char = byte.chr
          last_ascii = index + 1 >= data.bytesize
          allowed = last_ascii ? SAFE_ASCII : SAFE_ASCII_INTERNAL
          if allowed.include?(char)
            out << char
          else
            out << encode_byte(byte)
          end
          index += 1
        end
      end
      out
    end

    # A valid, non-ASCII UTF-8 character is safe when it is printable and
    # is neither a path separator. The +last+ flag marks the final
    # character of the name, in which case a space or dot is also encoded.
    def self.safe_unicode?(character, last = false)
      return false if character.ascii_only?
      return false if character == "/" || character == "\\"
      return false if character == "%"
      if last && (character == " " || character == "." || character =~ /\A\p{Zs}\z/ ||
                  character.ord == 0x00A0 || character.ord == 0xFEFF)
        return false
      end
      character =~ /\A[[:print:]]\z/
    end

    # Reverses NameMapper.escape, returning the original raw bytes as an
    # ASCII-8BIT string.
    def self.unescape(mapped)
      out = String.new.force_encoding(Encoding::ASCII_8BIT)
      mapped = String(mapped)
      index = 0
      while index < mapped.length
        char = mapped[index]
        if char == "%"
          hex = mapped[index + 1, 2]
          unless hex && hex =~ /\A[0-9A-Fa-f]{2}\z/
            raise InvalidNameError.new("malformed percent escape in #{mapped.inspect}", mapped.b)
          end
          out << hex.to_i(16).chr(Encoding::ASCII_8BIT)
          index += 3
        else
          out << String(char).force_encoding(Encoding::UTF_8).b
          index += 1
        end
      end
      out
    end

    # Length of the UTF-8 sequence beginning at +index+, or 1 when the byte
    # is an ASCII byte or a malformed/overlong lead.
    def self.utf8_sequence_length(data, index)
      lead = data.getbyte(index)
      expected =
        if lead >= 0xF0 then 4
        elsif lead >= 0xE0 then 3
        elsif lead >= 0xC2 then 2
        else return 1
        end
      (1...expected).each do |offset|
        following = data.getbyte(index + offset)
        return 1 unless following && (0x80..0xBF).include?(following)
      end
      expected
    end

    def self.encode_byte(byte)
      "%%%02X" % byte
    end

    private

      def default_reserved
        ->(name) { name =~ WINDOWS_RESERVED }
      end

      # Verifies the configured manifest name is itself a legal, self
      # contained local basename.
      def validate_manifest_name!
        name = manifest_name
        if name.empty? ||
           name.include?("/") || name.include?("\\") ||
           name == "." || name == ".." ||
           name =~ /[. ]\z/ ||
           name =~ /[[:cntrl:]]/ ||
           name.include?("%") ||
           (reserved_names && reserved_names.call(name))
          raise ArgumentError, "invalid manifest name: #{name.inspect}"
        end
      end

      def map_one(bytes)
        if strategy == :reject
          reject_or_keep(bytes)
        else
          escaped = self.class.escape(bytes)
          if reserved_names && reserved_names.call(escaped)
            # Reserved stems consist of safe ASCII letters, so force the
            # first byte to be encoded deterministically.
            escaped = "%%%02X" % escaped[0].ord + escaped[1..-1]
          end
          escaped
        end
      end

      # Under the :reject strategy, only valid UTF-8 names that contain no
      # forbidden byte are accepted verbatim.
      def reject_or_keep(bytes)
        verify_basename_bytes!(bytes)
        name = bytes.dup.force_encoding(Encoding::UTF_8)
        unless name.valid_encoding?
          raise InvalidNameError.new("remote name is not valid UTF-8: #{scrub(bytes)}", bytes)
        end
        unless name.each_char.all? { |character| character =~ /\A[[:print:]]\z/ }
          raise InvalidNameError.new("remote name contains a non-printable character: #{scrub(bytes)}", bytes)
        end
        if reserved_names && reserved_names.call(name)
          raise InvalidNameError.new("remote name is a platform reserved name: #{scrub(bytes)}", bytes)
        end
        name
      end

      # Byte level checks that never depend on the bytes forming valid
      # UTF-8. Keeping these independent guarantees that a name containing
      # an invalid sequence is rejected for the real reason and never
      # conflated with any other name through replacement characters.
      def verify_basename_bytes!(bytes)
        if bytes.include?("/".b) || bytes.include?("\\".b) || bytes.include?(0.chr.b)
          raise InvalidNameError.new("remote name contains a path separator: #{scrub(bytes)}", bytes)
        end
        if bytes == ".".b || bytes == "..".b
          raise InvalidNameError.new("remote name is a current/parent directory segment: #{scrub(bytes)}", bytes)
        end
        if bytes.each_byte.any? { |byte| byte < 0x20 || byte == 0x7F }
          raise InvalidNameError.new("remote name contains a control character: #{scrub(bytes)}", bytes)
        end
        last = bytes.getbyte(bytes.bytesize - 1)
        if last == ".".ord || last == " ".ord
          raise InvalidNameError.new("remote name ends with a space or dot: #{scrub(bytes)}", bytes)
        end
      end

      def register!(seen, key_source_name, mapped)
        key = equivalency.call(key_source_name)
        if seen.key?(key)
          raise NameCollisionError.new(
            "local name #{mapped.inspect} collides with #{seen[key].inspect} under the configured name equivalence",
            mapped
          )
        end
        seen[key] = mapped
      end

      # Diagnostic rendering that never silently conflates invalid bytes.
      def scrub(bytes)
        bytes.each_byte.map { |byte| byte < 0x20 || byte >= 0x7F ? "\\x%02X" % byte : byte.chr }.join
      end
  end

  # Default basename of the reverse-lookup manifest written into the
  # download destination.
  NameMapper::DEFAULT_MANIFEST_NAME = ".net-sftp-name-map"

end; end; end
