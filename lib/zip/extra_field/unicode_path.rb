# frozen_string_literal: true

require_relative 'generic'

module Zip
  # Info-ZIP Unicode Path extra field (0x7075). Stores a UTF-8 copy of the
  # entry name, along with a CRC32 of the name bytes stored in the header
  # this field accompanies, so that readers can tell whether the UTF-8 copy
  # actually corresponds to the header name.
  class ExtraField::UnicodePath < ExtraField::Generic
    HEADER_ID = 'up'
    register_map

    # The default would be :unicodepath; use the more readable :unicode_path.
    def self.name
      :unicode_path
    end

    # The field version (should be 1).
    attr_reader :version

    # The CRC32 of the accompanying header's name bytes, as declared by
    # this field.
    attr_reader :name_crc32

    # The raw bytes of the UTF-8 name stored in this field.
    attr_reader :unicode_name

    def initialize(binstr = nil)
      super()
      @version = nil
      @name_crc32 = nil
      @unicode_name = nil
      merge(binstr) unless binstr.nil?
    end

    def merge(binstr)
      return if binstr.empty?
      return unless @unicode_name.nil? # First occurrence wins.

      size, content = initial_parse(binstr)
      return if !size || content.bytesize < 5

      @version, @name_crc32 = content.unpack('CV')
      @unicode_name = content[5..]
    end

    # The name stored in this field, decoded as UTF-8.
    def decoded_name
      @unicode_name&.dup&.force_encoding('UTF-8')
    end

    # Is the stored name valid UTF-8?
    def valid_utf8?
      !decoded_name.nil? && decoded_name.valid_encoding?
    end

    # Does the declared CRC32 match the given raw header name bytes?
    def crc_valid_for?(raw_name)
      !@name_crc32.nil? && @name_crc32 == Zlib.crc32(raw_name)
    end

    def ==(other)
      @version == other.version &&
        @name_crc32 == other.name_crc32 &&
        @unicode_name == other.unicode_name
    end

    def pack_for_local
      pack_content
    end

    def pack_for_c_dir
      pack_content
    end

    private

    def pack_content
      return +'' if @unicode_name.nil?

      [@version, @name_crc32].pack('CV') << @unicode_name
    end
  end
end
