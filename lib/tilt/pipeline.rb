require_relative 'template'

module Tilt
  # Superclass used for pipeline templates.  Should not be used directly.
  class Pipeline < Template
    def prepare
      templates = self.class::TEMPLATES
      input_encodings = self.class.const_get(:INPUT_ENCODINGS)
      output_encodings = self.class.const_get(:OUTPUT_ENCODINGS)

      @pipeline = templates.each_with_index.inject(proc{|*| data}) do |previous, ((klass, options), index)|
        proc do |s,l,&sb|
          stage_data = previous.call(s, l, &sb)
          stage_data = convert_stage_encoding(stage_data, input_encodings[index], :input, index)

          output = klass.new(file, line, options, &proc{|*| stage_data}).render(s, l, &sb)
          convert_stage_encoding(output, output_encodings[index], :output, index)
        end
      end
    end

    def evaluate(scope, locals, &block)
      @pipeline.call(scope, locals, &block)
    end

    private

    def convert_stage_encoding(data, target_encoding, direction, stage)
      return data if target_encoding.nil? || !data.respond_to?(:force_encoding)

      if data.encoding == Encoding::BINARY
        converted = normalize_binary_encoding(data, target_encoding, stage, direction)
      elsif data.encoding == target_encoding
        converted = validate_declared_encoding(data, stage, direction)
      else
        converted = transcode_encoding(data, target_encoding, stage, direction)
      end

      remove_bom(converted)
    end

    def normalize_binary_encoding(data, target_encoding, stage, direction)
      return data if target_encoding == Encoding::BINARY

      converted = data.dup
      converted.force_encoding(target_encoding)
      validate_declared_encoding(converted, stage, direction)
    end

    def validate_declared_encoding(data, stage, direction)
      return data if data.valid_encoding?

      compatible_encoding = Encoding::Converter.asciicompat_encoding(data.encoding)
      if compatible_encoding
        converter = Encoding::Converter.new(data.encoding, compatible_encoding)
        source = data.dup
        destination = String.new
        result = converter.primitive_convert(source, destination, nil, nil, :partial_input => false)
        unless result == :finished
          raise conversion_error(converter, data, source, stage, direction, result, data.encoding.name)
        end
        data
      else
        byte_position = invalid_byte_position(data)
        raise Encoding::InvalidByteSequenceError,
          "#{stage_label(stage, direction)} invalid byte sequence in #{data.encoding} at byte #{byte_position}"
      end
    end

    def transcode_encoding(data, target_encoding, stage, direction)
      source_encoding = data.encoding

      converter = Encoding::Converter.new(source_encoding, target_encoding)
      source = data.dup
      destination = String.new.force_encoding(target_encoding)
      result = converter.primitive_convert(source, destination, nil, nil, :partial_input => false)
      return destination if result == :finished

      raise conversion_error(converter, data, source, stage, direction, result)
    end

    def conversion_error(converter, original, source, stage, direction, result, target_name=nil)
      error_info = converter.primitive_errinfo
      byte_position = original.bytesize - source.bytesize - error_info[3].bytesize
      byte_position = 0 if byte_position < 0
      exception_class = result == :undefined_conversion ? Encoding::UndefinedConversionError : Encoding::InvalidByteSequenceError
      target_name ||= error_info[2] || original.encoding.name
      message = "#{stage_label(stage, direction)} #{target_name}: #{result} at byte #{byte_position}"
      exception_class.new(message)
    end

    def invalid_byte_position(data)
      position = 0
      data.each_codepoint do |codepoint|
        position += codepoint.chr(data.encoding).dup.force_encoding(Encoding::BINARY).bytesize
      end
      position
    rescue EncodingError, ArgumentError
      position
    end

    def remove_bom(data)
      return data if data.empty? || data.encoding == Encoding::BINARY

      bytes = data.dup.force_encoding(Encoding::BINARY)
      bom = byte_order_mark(bytes, data.encoding)
      return data unless bom

      bytes.byteslice(bom.bytesize, bytes.bytesize).force_encoding(data.encoding)
    end

    def byte_order_mark(data, encoding)
      boms = {
        Encoding::UTF_8 => ["\xEF\xBB\xBF".b],
        Encoding::UTF_16BE => ["\xFE\xFF".b],
        Encoding::UTF_16LE => ["\xFF\xFE".b],
        Encoding::UTF_32BE => ["\x00\x00\xFE\xFF".b],
        Encoding::UTF_32LE => ["\xFF\xFE\x00\x00".b]
      }

      boms[encoding] && boms[encoding].find { |bom| data.start_with?(bom) }
    end

    def stage_label(stage, direction)
      klass = self.class::TEMPLATES[stage][0]
      name = self.class.const_get(:TEMPLATE_EXTENSIONS)[stage] || klass.name
      "pipeline stage #{stage + 1} (#{name}) #{direction}:"
    end
  end
end
