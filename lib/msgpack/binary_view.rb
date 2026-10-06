# frozen_string_literal: true

module MessagePack
  class Unpacker
    class BinaryView < String
      def initialize(data = "", zero_copy = false)
        super(data)
        @zero_copy = zero_copy
        force_encoding(Encoding::ASCII_8BIT)
        freeze
      end

      def self._native_alloc
        allocate
      end
      private_class_method :_native_alloc

      def zero_copy?
        @zero_copy
      end

      def byteslice(*args)
        slice = super
        return nil if slice.nil?
        self.class.send(:new, slice, false)
      end

      alias_method :slice, :byteslice
      alias_method :[], :byteslice

      def write_to(io)
        io.write(to_str)
        bytesize
      end

      private

      def _native_finish(zero_copy)
        @zero_copy = zero_copy
        force_encoding(Encoding::ASCII_8BIT)
        freeze
      end

      def initialize_copy(source)
        super
        @zero_copy = false
      end
    end
  end
end
