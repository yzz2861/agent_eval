# frozen_string_literal: true

require "stringio"

class MessagePack::StrToBinConverter
  class Error < MessagePack::UnpackError; end
  class MalformedWireError < MessagePack::MalformedFormatError; end

  class PathTypeMismatchError < Error
    attr_reader :path, :type, :offset

    def initialize(path, type, offset)
      @path = path
      @type = type
      @offset = offset
      super("#{path.inspect} expected a MessagePack string but found #{type}")
    end
  end

  class PathSegment
    attr_reader :kind, :value, :label

    def initialize(kind, value, label = value)
      @kind = kind
      @value = value
      @label = label
    end

    def ==(other)
      other.is_a?(PathSegment) && kind == other.kind && value == other.value
    end
    alias eql? ==

    def hash
      [kind, value].hash
    end

    def inspect
      kind == :array ? "[#{label}]" : label.inspect
    end
  end

  class Path
    attr_reader :segments

    def self.root
      new([])
    end

    def self.map(key)
      root.map(key)
    end

    def self.index(position)
      root.index(position)
    end

    def initialize(segments)
      @segments = segments
    end

    def map(key)
      append(PathSegment.new(:map, key_matcher(key), key))
    end

    def index(position)
      unless position.is_a?(Integer) && position >= 0
        raise ArgumentError, "array position must be a non-negative integer"
      end

      append(PathSegment.new(:array, position, position))
    end

    def append(segment)
      self.class.new(segments + [segment])
    end

    def +(other)
      self.class.new(segments + other.segments)
    end

    def empty?
      segments.empty?
    end

    def ==(other)
      other.is_a?(Path) && segments == other.segments
    end
    alias eql? ==

    def hash
      segments.hash
    end

    def inspect
      segments.map { |segment| segment.kind == :array ? "[#{segment.label}]" : %([#{segment.label.inspect}]) }.join
    end

    private

    def key_matcher(key)
      case key
      when String
        if key.encoding == Encoding::ASCII_8BIT
          [:bin, key.dup.b]
        else
          [:string, key.encode(Encoding::UTF_8).b]
        end
      when Symbol
        [:string, key.to_s.encode(Encoding::UTF_8).b]
      when Integer
        key
      when Float
        [:float, key]
      when nil, true, false
        key
      when MessagePack::ExtensionValue
        [:extension, signed_type(key.type), key.payload.b]
      else
        raise ArgumentError, "map key must be a primitive MessagePack value"
      end
    end

    def signed_type(type)
      type < 128 ? type : type - 256
    end
  end

  Mismatch = Struct.new(:path, :type, :offset)
  Result = Struct.new(:output, :mismatches)

  Node = Struct.new(:segment, :children, :terminal) do
    def initialize
      self.segment = nil
      self.children = {}
      self.terminal = false
    end
  end

  COPY_CHUNK_SIZE = 64 * 1024

  def self.convert(source, *paths, on_non_string: :raise, output: nil)
    new(*paths, on_non_string: on_non_string).convert(source, output).output
  end

  def initialize(*paths, on_non_string: :raise)
    unless %i[raise skip].include?(on_non_string)
      raise ArgumentError, "on_non_string must be :raise or :skip"
    end

    @root = Node.new
    paths.each { |path| add_path(path) }
    @on_non_string = on_non_string
  end

  def convert(source, output = nil)
    input = source.is_a?(String) ? StringIO.new(source.b) : source
    input.binmode if input.respond_to?(:binmode)

    destination = output || StringIO.new
    destination.binmode if destination.respond_to?(:binmode)
    mismatches = []

    session = Session.new(input, destination, @root, @on_non_string, mismatches)
    session.process_value(@root, Path.root)

    if source.is_a?(String) && input.read(1)
      raise MalformedWireError, "extra bytes after MessagePack value"
    end

    converted_output = output || destination.string.b
    Result.new(converted_output, mismatches)
  end

  alias call convert

  private

  def add_path(path)
    unless path.is_a?(Path)
      raise ArgumentError, "expected a #{Path}"
    end

    node = @root
    path.segments.each do |segment|
      node = node.children[segment] ||= begin
        child = Node.new
        child.segment = segment
        child
      end
    end
    node.terminal = true
  end

  class Session
    def initialize(input, output, root, on_non_string, mismatches)
      @input = input
      @output = output
      @current_output = output
      @on_non_string = on_non_string
      @mismatches = mismatches
      @offset = 0
    end

    def process_value(node, path)
      value_offset = @offset
      info = read_header

      if info[:kind] == :string && node.terminal
        write_converted_string_header(info)
        copy_payload(info[:body_length])
        return
      end

      if node.terminal && info[:kind] != :string
        mismatch = Mismatch.new(path, info[:kind], value_offset)
        @mismatches << mismatch
        if @on_non_string == :raise
          raise PathTypeMismatchError.new(path, info[:kind], value_offset)
        end
      end

      write_bytes(info[:header])
      descend(info, node, path)
    end

    def copy_value
      info = read_header
      write_bytes(info[:header])
      copy_or_descend(info) { |child| copy_value }
    end

    private

    def descend(info, node, path)
      case info[:kind]
      when :array
        info[:body_length].times do |position|
          segment = PathSegment.new(:array, position, position)
          child_node = node.children[segment]
          child_path = path.append(child_node&.segment || segment)
          process_value(child_node || Node.new, child_path)
        end
      when :map
        info[:body_length].times do
          child_node = copy_map_key(node)
          process_map_value(child_node, node, path)
        end
      else
        copy_payload(info[:body_length])
      end
    end

    def copy_or_descend(info)
      case info[:kind]
      when :array
        info[:body_length].times { yield }
      when :map
        info[:body_length].times do
          copy_value
          yield
        end
      else
        copy_payload(info[:body_length])
      end
    end

    def process_map_value(child_node, _parent_node, path)
      if child_node
        process_value(child_node, path.append(child_node.segment))
      else
        copy_value
      end
    end

    def container?(info)
      info[:kind] == :array || info[:kind] == :map
    end

    def copy_map_key(parent_node)
      info = read_header
      write_bytes(info[:header])

      if container?(info)
        copy_or_descend(info) { copy_value }
        return nil
      end

      payload = read_payload(info[:body_length])
      write_bytes(payload)
      key_value = wire_key_value(info, payload)
      return nil if key_value.nil? && info[:kind] != :nil

      segment = PathSegment.new(:map, key_value, info[:header] + payload)
      parent_node.children[segment]
    end

    def wire_key_value(info, payload)
      case info[:kind]
      when :string
        [:string, payload]
      when :bin
        [:bin, payload]
      when :integer
        decode_integer(info[:byte], payload)
      when :float
        [:float, payload.unpack1(info[:byte] == 0xca ? "g" : "G")]
      when :extension
        type_byte = info[:header].getbyte(-1)
        [:extension, type_byte < 128 ? type_byte : type_byte - 256, payload]
      when :nil
        nil
      when :true
        true
      when :false
        false
      end
    end

    def decode_integer(byte, payload)
      case byte
      when 0x00..0x7f, 0xe0..0xff
        byte < 0xe0 ? byte : byte - 256
      when 0xcc
        payload.getbyte(0)
      when 0xcd
        payload.unpack1("S>")
      when 0xce
        payload.unpack1("L>")
      when 0xcf
        payload.unpack1("Q>")
      when 0xd0
        payload.unpack1("c")
      when 0xd1
        payload.unpack1("s>")
      when 0xd2
        payload.unpack1("l>")
      when 0xd3
        payload.unpack1("q>")
      end
    end

    def write_converted_string_header(info)
      case info[:byte]
      when 0xa0..0xbf
        write_bytes([0xc4, info[:body_length]].pack("CC"))
      when 0xd9
        write_bytes("\xc4".b + info[:header].byteslice(1, 1))
      when 0xda
        write_bytes("\xc5".b + info[:header].byteslice(1, 2))
      when 0xdb
        write_bytes("\xc6".b + info[:header].byteslice(1, 4))
      end
    end

    def read_header
      offset = @offset
      byte = read_byte
      kind, body_length, header = header_for(byte, offset)
      {byte: byte, kind: kind, body_length: body_length, header: header, offset: offset}
    rescue EOFError
      raise MalformedWireError, "unexpected end of MessagePack data"
    rescue MalformedWireError
      raise
    rescue => error
      raise MalformedWireError, error.message
    end

    def header_for(byte, offset)
      case byte
      when 0x00..0x7f, 0xe0..0xff
        [:integer, 0, byte.chr]
      when 0xc0
        [:nil, 0, byte.chr]
      when 0xc2
        [:false, 0, byte.chr]
      when 0xc3
        [:true, 0, byte.chr]
      when 0xca
        [:float, 4, byte.chr]
      when 0xcb
        [:float, 8, byte.chr]
      when 0xcc, 0xd0
        [:integer, 1, byte.chr]
      when 0xcd, 0xd1
        [:integer, 2, byte.chr]
      when 0xce, 0xd2
        [:integer, 4, byte.chr]
      when 0xcf, 0xd3
        [:integer, 8, byte.chr]
      when 0xa0..0xbf
        [:string, byte & 0x1f, byte.chr]
      when 0xc4
        header = byte.chr + read_payload(1)
        [:bin, unsigned(header.byteslice(1, 1)), header]
      when 0xc5
        header = byte.chr + read_payload(2)
        [:bin, unsigned(header.byteslice(1, 2)), header]
      when 0xc6
        header = byte.chr + read_payload(4)
        [:bin, unsigned(header.byteslice(1, 4)), header]
      when 0xd9
        header = byte.chr + read_payload(1)
        [:string, unsigned(header.byteslice(1, 1)), header]
      when 0xda
        header = byte.chr + read_payload(2)
        [:string, unsigned(header.byteslice(1, 2)), header]
      when 0xdb
        header = byte.chr + read_payload(4)
        [:string, unsigned(header.byteslice(1, 4)), header]
      when 0x90..0x9f
        [:array, byte & 0x0f, byte.chr]
      when 0xdc
        header = byte.chr + read_payload(2)
        [:array, unsigned(header.byteslice(1, 2)), header]
      when 0xdd
        header = byte.chr + read_payload(4)
        [:array, unsigned(header.byteslice(1, 4)), header]
      when 0x80..0x8f
        [:map, byte & 0x0f, byte.chr]
      when 0xde
        header = byte.chr + read_payload(2)
        [:map, unsigned(header.byteslice(1, 2)), header]
      when 0xdf
        header = byte.chr + read_payload(4)
        [:map, unsigned(header.byteslice(1, 4)), header]
      when 0xd4..0xd8
        type = read_payload(1)
        [:extension, FIXED_EXT_LENGTH.fetch(byte), byte.chr + type]
      when 0xc7
        length_bytes = read_payload(1)
        length = unsigned(length_bytes)
        type = read_payload(1)
        [:extension, length, byte.chr + length_bytes + type]
      when 0xc8
        length_bytes = read_payload(2)
        length = unsigned(length_bytes)
        type = read_payload(1)
        [:extension, length, byte.chr + length_bytes + type]
      when 0xc9
        length_bytes = read_payload(4)
        length = unsigned(length_bytes)
        type = read_payload(1)
        [:extension, length, byte.chr + length_bytes + type]
      else
        raise MalformedWireError, "unsupported MessagePack type byte 0x#{byte.to_s(16)} at byte #{offset}"
      end
    end

    def unsigned(bytes)
      bytes.each_byte.reduce(0) { |value, item| (value << 8) | item }
    end

    def read_byte
      read_payload(1).getbyte(0)
    end

    def read_payload(size)
      value = @input.read(size)
      unless value && value.bytesize == size
        raise EOFError, "expected #{size} bytes"
      end

      @offset += value.bytesize
      value.b
    end

    def copy_payload(size)
      remaining = size
      while remaining > 0
        chunk = @input.read([remaining, COPY_CHUNK_SIZE].min)
        unless chunk && !chunk.empty?
          raise MalformedWireError, "unexpected end of MessagePack data"
        end

        @offset += chunk.bytesize
        write_bytes(chunk)
        remaining -= chunk.bytesize
      end
    end

    def write_bytes(bytes)
      @current_output.write(bytes.b)
    end

    FIXED_EXT_LENGTH = {
      0xd4 => 1,
      0xd5 => 2,
      0xd6 => 4,
      0xd7 => 8,
      0xd8 => 16,
    }.freeze
  end

  private_constant :Node
end
