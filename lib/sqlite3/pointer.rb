module SQLite3
  if const_defined?(:Pointer, false)
    # An opaque pointer to a Ruby object while it is being passed between application-defined SQL
    # functions. Pointer values have SQLite's NULL storage class, so they cannot be written into
    # tables and ordinary SQL expressions can only see them as +NULL+.
    #
    # The object can only be retrieved with the same type label supplied when the pointer was
    # created. A mismatching label returns +nil+ rather than returning an unrelated object.
    #
    #   calculator = MyCalculator.new
    #   db.define_function("echo_calculator") { |value| value }
    #   db.define_function("calculate") do |value|
    #     calculator = SQLite3::Pointer.get(value, "calculator")
    #     calculator&.result
    #   end
    #
    #   db.get_first_value("SELECT calculate(echo_calculator(?))", [
    #     SQLite3::Pointer.new("calculator", calculator)
    #   ])
    class Pointer
      # Create a typed pointer carrying +object+. +type+ may be a String or Symbol.
      # @!method initialize(type, object)

      # @return [String] the exact type label required to retrieve the carried object
      # @!method type

      # Retrieve +pointer+ when it is a Pointer and +type+ matches.
      # @!method self.get(pointer, type)
    end
  end
end
