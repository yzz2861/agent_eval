require "set"

module Dotenv
  # Raised when a value contains a command substitution that the
  # {Dotenv::CommandPolicy} in effect does not allow to be executed.
  class CommandNotAllowedError < StandardError; end

  # Raised when an executor supplied by the caller reports a failure or raises
  # while handling a command substitution.
  class CommandExecutionError < StandardError
    attr_reader :location

    def initialize(message = nil, location: nil)
      @location = location
      super(message)
    end
  end

  # Location of a command substitution inside the source being parsed.
  CommandLocation = Struct.new(:filename, :line, keyword_init: true) do
    def to_s
      suffix = line ? ":#{line}" : ""
      "#{filename || "(raw input)"}#{suffix}"
    end
  end

  # Explicit outcome of a caller-provided command executor.
  #
  # Use {CommandResult.success} or {CommandResult.failure} rather than calling
  # the constructor directly. Returning any other object from an executor is
  # also treated as a successful result.
  class CommandResult
    class << self
      def success(value)
        new(true, value, nil)
      end

      def failure(message)
        new(false, nil, message)
      end
    end

    attr_reader :value, :error

    def initialize(success, value, error)
      @success = success
      @value = value
      @error = error
    end

    def success?
      @success
    end
  end

  # Per-load policy describing how `$(...)` command substitutions are handled.
  #
  # Three independent modes are supported:
  #
  # * +:disabled+ (default) - raises {CommandNotAllowedError} for any command
  #   substitution. Nothing is executed.
  # * +:literal+ - leaves command substitutions untouched in the value. Nothing
  #   is executed.
  # * +:shell+ - executes commands with the system shell (the historical
  #   dotenv behavior).
  # * a callable executor - the executor is invoked with the command text, a
  #   read-only view of the variables visible at that point, and the source
  #   location. It must return a {CommandResult} (or any object used verbatim as
  #   the substitution value) or {CommandResult.failure}; the system shell is
  #   never used as a fallback.
  class CommandPolicy
    MODES = Set[:disabled, :literal, :shell].freeze

    # @return [CommandPolicy] the policy used when the caller does not specify one
    def self.default
      new(:disabled)
    end

    # Coerce a user supplied option into a policy.
    #
    # @param policy [Symbol, #call, CommandPolicy, nil] the requested policy
    # @return [CommandPolicy]
    def self.coerce(policy)
      case policy
      when nil then default
      when CommandPolicy then policy
      when Symbol, Proc, Method
        new(policy)
      else
        if policy.respond_to?(:call)
          new(policy)
        else
          raise ArgumentError,
            "Invalid command policy #{policy.inspect}. " \
            "Use :disabled, :literal, :shell, or a callable executor."
        end
      end
    end

    attr_reader :mode

    def initialize(mode)
      if mode.is_a?(Symbol)
        raise ArgumentError, "Unknown command policy #{mode.inspect}" unless MODES.include?(mode)
      elsif !mode.respond_to?(:call)
        raise ArgumentError, "Command policy must be :disabled, :literal, :shell, or callable"
      end

      @mode = mode
    end

    def disabled?
      mode == :disabled
    end

    def literal?
      mode == :literal
    end

    def shell?
      mode == :shell
    end

    def executor?
      !mode.is_a?(Symbol)
    end

    # Invoke the caller provided executor.
    #
    # @param command [String] raw command text, nested commands already resolved
    # @param view [Hash] frozen variables visible at this point
    # @param location [CommandLocation] source location of the substitution
    # @return [String] value to substitute
    def execute(command, view, location)
      result =
        begin
          mode.call(command, view, location)
        rescue StandardError => e
          raise CommandExecutionError.new(
            "Command #{command.inspect} failed at #{location}: #{e.message}",
            location: location
          )
        end

      if result.is_a?(CommandResult)
        if result.success?
          result.value.to_s
        else
          raise CommandExecutionError.new(
            "Command #{command.inspect} failed at #{location}: #{result.error}",
            location: location
          )
        end
      else
        result.to_s
      end
    end
  end
end
