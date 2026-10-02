module Tilt
  # Raised when the locals passed to a template do not satisfy the
  # locals contract declared by that template.
  class LocalsError < ArgumentError
  end

  # Wraps a block used to lazily compute the default value of an optional
  # local on every render. Use this when the default is a mutable object or
  # when computing it can fail:
  #
  #   Tilt::ERBTemplate.new(nil, 1, :locals => {
  #     :items => Tilt::Default.new { [] }
  #   }) { template_source }
  #
  # A plain +proc+/+lambda+ given as a default value is treated the same way.
  class Default
    def initialize(&block)
      raise ArgumentError, "Tilt::Default requires a block" unless block
      @block = block
    end

    # Evaluate the default for a single render. The returned value is used
    # as-is and is never shared with another render.
    def call
      @block.call
    end
  end

  # Describes the locals a template accepts: which are required, which are
  # optional together with their default values, and whether locals that are
  # not part of the contract are allowed.
  #
  # This is an internal object built by Template; it is not meant to be
  # instantiated directly by user code.
  class LocalsContract
    # Sorted Array of declared local names (Symbols), required and optional.
    attr_reader :keys

    # Sorted Array of required local names (Symbols).
    attr_reader :required_keys

    def self.normalize_name(key)
      name = key.to_s
      unless name =~ /\A[a-z_][a-zA-Z_0-9]*\z/
        raise ArgumentError, "invalid locals key: #{key.inspect} (keys must be variable names)"
      end
      name.to_sym
    end

    # +required+ is an Array of names and +defaults+ is a Hash mapping optional
    # names to their default values.
    def initialize(required, defaults, allow_extra=false)
      required = required.map { |key| self.class.normalize_name(key) }.uniq.sort
      defaults = defaults.each_with_object({}) do |(key, value), hash|
        hash[self.class.normalize_name(key)] = value
      end

      overlap = required & defaults.keys
      unless overlap.empty?
        raise ArgumentError, "local declared both required and optional: #{overlap.inspect}"
      end

      @required_keys = required.freeze
      @keys = (required + defaults.keys).sort.freeze
      @defaults = defaults
      @allow_extra = allow_extra
    end

    def allow_extra?
      @allow_extra
    end

    # Validate +locals+ and return a new Hash containing every declared local:
    # provided values win, missing optionals are filled in with freshly
    # evaluated defaults. Raises LocalsError for unknown or missing names.
    def materialize(locals)
      supplied = supplied_keys(locals)

      extras = supplied - @keys
      unless @allow_extra || extras.empty?
        raise LocalsError, "unexpected locals #{extras.inspect}; #{@keys.inspect} are declared"
      end

      missing = @required_keys - supplied
      unless missing.empty?
        raise LocalsError, "missing required locals #{missing.inspect}"
      end

      materialized = {}
      @keys.each do |key|
        if has_local?(locals, key)
          materialized[key] = get_local(locals, key)
        else
          materialized[key] = evaluate_default(@defaults[key])
        end
      end

      # Keep allowed, undeclared locals for interpreted adapters that accept
      # arbitrary locals. Compiled methods only bind the declared @keys.
      if @allow_extra
        locals.each do |key, value|
          materialized[key] = value unless has_local?(materialized, key)
        end
      end

      materialized
    end

    private

    def supplied_keys(locals)
      keys = []
      locals.each_key do |key|
        case key
        when Symbol then keys << key
        when String then keys << key.to_sym
        else keys << key
        end
      end
      keys.uniq
    end

    def has_local?(locals, key)
      locals.key?(key) || locals.key?(key.to_s)
    end

    def get_local(locals, key)
      locals.key?(key) ? locals[key] : locals[key.to_s]
    end

    def evaluate_default(default)
      value = default.is_a?(Default) ? default.call : default
      fresh_value(value)
    end

    # Return a per-render copy of mutable default values so the same object is
    # never shared across renders. Immutable values are shared safely, and a
    # Tilt::Default block fully owns the value it returns.
    def fresh_value(value)
      case value
      when nil, true, false, Symbol, Numeric
        value
      when String
        value.frozen? ? value : value.dup
      when Array
        value.map { |item| fresh_value(item) }
      when Hash
        copy = value.class.new
        value.each { |k, v| copy[fresh_value(k)] = fresh_value(v) }
        copy.default_proc = value.default_proc if value.default_proc
        copy.default = fresh_value(value.default) if !value.default_proc && value.default
        copy
      else
        begin
          Marshal.load(Marshal.dump(value))
        rescue TypeError, ArgumentError
          value
        end
      end
    end
  end
end
