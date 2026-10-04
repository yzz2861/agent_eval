# frozen_string_literal: true

require_relative 'generic'

module Zip
  # Info-ZIP Unicode Path Extra Field (0x7075). Stores a UTF-8 version of
  # the entry name, along with a CRC32 of the raw bytes of the name stored
  # in the enclosing (local or central directory) header, so that readers
  # can tell whether the UTF-8 name still belongs to that header name.
  class ExtraField::UnicodePath < ExtraField::Generic
    HEADER_ID = [0x7075].pack('v')
    register_map

    VERSION = 1

    attr_reader :version, :name_crc32, :unicode_name

    def initialize(binstr = nil)
      @version      = nil
      @name_crc32   = nil
      @unicode_name = nil
      merge(binstr) if binstr
    end

    def merge(binstr)
      return if binstr.empty?

      size, content = initial_parse(binstr)
      return unless size && content && content.bytesize >= 5

      @version      = content.getbyte(0)
      @name_crc32   = content[1, 4].unpack1('V')
      @unicode_name = content[5..] || +''
    end

    # True when the stored CRC32 matches the CRC32 of the given raw header
    # name bytes, i.e. this UTF-8 name really belongs to that header name.
    def crc_matches?(raw_name_bytes)
      !@name_crc32.nil? && @name_crc32 == ::Zlib.crc32(raw_name_bytes)
    end

    def ==(other)
      other.version == @version &&
        other.name_crc32 == @name_crc32 &&
        other.unicode_name == @unicode_name
    end

    def pack_for_local
      return +'' if @version.nil?

      [@version, @name_crc32].pack('CV') << @unicode_name.dup.force_encoding(Encoding::BINARY)
    end

    alias pack_for_c_dir pack_for_local
  end
end
