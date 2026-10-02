module Tilt
  # @private
  module CompiledTemplates
  end

  # @private
  TOPOBJECT = CompiledTemplates

  # @private
  LOCK = Mutex.new

  # Error raised when the locals given to Template#render do not satisfy
  # the locals contract declared for the template, or when evaluating the
  # default value for an optional local fails.  The error message includes
  # the template's file and line.
  class LocalsContractError < ArgumentError
  end

  # A locals contract describes the locals a template expects: which
  # locals are required, which locals are optional (with default values),
  # and whether locals not declared in the contract are allowed.
  #
  # Contracts are declared as hashes:
  #
  #   {
  #     required: [:name],              # locals that must be provided
  #     optional: {title: 'untitled'},  # locals with default values
  #     allow_extra: false,             # whether undeclared locals are allowed
  #   }
  #
  # When a template has a contract, Template#render checks the given
  # locals against the contract before the template body is evaluated:
  #
  # * A missing required local raises LocalsContractError.
  # * An undeclared local raises LocalsContractError, unless the contract
  #   allows extra locals.
  # * Omitted optional locals are set to their default values.  Defaults
  #   that respond to #call are called on every render; other defaults are
  #   duplicated (with #dup) on every render, so mutable default values
  #   are never shared between renders.  If evaluating a default raises,
  #   a LocalsContractError is raised and the template body is not
  #   evaluated.
  #
  # After validation, locals are canonicalized to the names declared in
  # the contract (plus any extra locals, if allowed), so templates with a
  # contract compile a single method per scope class, regardless of the
  # order or subset of locals each render provides.
  class LocalsContract
    # Array of required local names, as symbols.
    attr_reader :required

    # Hash of optional local names (symbols) to their default values.
    attr_reader :optional

    def initialize(contract)
      unless contract.respond_to?(:to_hash)
        raise ArgumentError, "locals contract must be a hash: #{contract.inspect}"
      end
      contract = contract.to_hash

      @required = Array(contract[:required]).map { |name| normalize_name(name) }.freeze
      if @required != @required.uniq
        raise ArgumentError, "duplicate required locals in contract: #{@required.inspect}"
      end

      optional = contract[:optional] || {}
      unless optional.respond_to?(:to_hash)
        raise ArgumentError, "optional locals in contract must be a hash of names to defaults: #{optional.inspect}"
      end
      @optional = {}
      optional.to_hash.each_pair do |name, default|
        @optional[normalize_name(name)] = default
      end
      @optional.freeze

      overlap = @required & @optional.keys
      unless overlap.empty?
        raise ArgumentError, "locals cannot be both required and optional: #{overlap.inspect}"
      end

      @allow_extra = contract[:allow_extra] ? true : false
      @names = (@required + @optional.keys).freeze
    end

    # Whether locals not declared in the contract are allowed.
    def allow_extra?
      @allow_extra
    end

    # Check the given locals against the contract for the given template,
    # and return the canonical locals hash to evaluate the template with.
    # Raises LocalsContractError if the locals do not satisfy the contract
    # or a default value cannot be evaluated.
    def resolve(locals, template)
      location = "#{template.eval_file}:#{template.line}"
      provided = {}
      extra = {}

      locals.each_pair do |key, value|
        name = begin
          key.to_sym
        rescue NoMethodError
          nil
        end

        if name && @names.include?(name)
          provided[name] = value
        else
          extra[key] = value
        end
      end

      @required.each do |name|
        unless provided.key?(name)
          raise LocalsContractError, "#{location}: missing required local: #{name.inspect}"
        end
      end

      unless allow_extra? || extra.empty?
        names = extra.keys.map { |key| key.inspect }.join(', ')
        raise LocalsContractError, "#{location}: unexpected locals: #{names}"
      end

      resolved = {}
      @required.each do |name|
        resolved[name] = provided[name]
      end
      @optional.each do |name, default|
        resolved[name] = if provided.key?(name)
          provided[name]
        else
          evaluate_default(name, default, location)
        end
      end
      extra.each_pair do |key, value|
        resolved[key] = value
      end
      resolved
    end

    private

    def normalize_name(name)
      unless name.respond_to?(:to_sym)
        raise ArgumentError, "local names in contracts must be strings or symbols: #{name.inspect}"
      end
      name.to_sym
    end

    def evaluate_default(name, default, location)
      if default.respond_to?(:call)
        default.call
      else
        default.dup
      end
    rescue => e
      raise LocalsContractError, "#{location}: default for local #{name.inspect} failed: #{e.message} (#{e.class})"
    end
  end

  # Base class for template implementations. Subclasses must implement
  # the #prepare method and one of the #evaluate or #precompiled_template
  # methods.
  class Template
    # Template source; loaded from a file or given directly.
    attr_reader :data

    # The name of the file where the template data was loaded from.
    attr_reader :file

    # The line number in #file where template data was loaded from.
    attr_reader :line

    # A Hash of template engine specific options. This is passed directly
    # to the underlying engine and is not used by the generic template
    # interface.
    attr_reader :options

    # A path ending in .rb that the template code will be written to, then
    # required, instead of being evaled.  This is useful for determining
    # coverage of compiled template code, or to use static analysis tools
    # on the compiled template code.
    attr_reader :compiled_path

    # The LocalsContract declared for this template, or nil if the
    # template does not declare a locals contract.
    attr_reader :locals_contract

    class << self
      # An empty Hash that the template engine can populate with various
      # metadata.
      def metadata
        @metadata ||= {}
      end

      # The locals contract declared for this template class, or nil if no
      # contract is declared.  Contracts set on a class are inherited by
      # subclasses, and can be overridden per template instance with the
      # :locals_contract option.  See LocalsContract for the contract
      # format.
      def locals_contract
        if defined?(@locals_contract)
          @locals_contract
        elsif superclass.respond_to?(:locals_contract)
          superclass.locals_contract
        end
      end

      # Declare the locals contract used by default for instances of this
      # template class.  See LocalsContract for the contract format.
      def locals_contract=(contract)
        @locals_contract = contract
      end

      # @deprecated Use `.metadata[:mime_type]` instead.
      def default_mime_type
        metadata[:mime_type]
      end

      # @deprecated Use `.metadata[:mime_type] = val` instead.
      def default_mime_type=(value)
        metadata[:mime_type] = value
      end
    end

    # Create a new template with the file, line, and options specified. By
    # default, template data is read from the file. When a block is given,
    # it should read template data and return as a String. When file is nil,
    # a block is required.
    #
    # All arguments are optional.
    def initialize(file=nil, line=1, options={}, &block)
      @file, @line, @options = nil, 1, {}

      [options, line, file].compact.each do |arg|
        case
        when arg.respond_to?(:to_str)  ; @file = arg.to_str
        when arg.respond_to?(:to_int)  ; @line = arg.to_int
        when arg.respond_to?(:to_hash) ; @options = arg.to_hash.dup
        when arg.respond_to?(:path)    ; @file = arg.path
        when arg.respond_to?(:to_path) ; @file = arg.to_path
        else raise TypeError, "Can't load the template file. Pass a string with a path " +
          "or an object that responds to 'to_str', 'path' or 'to_path'"
        end
      end

      raise ArgumentError, "file or block required" if (@file || block).nil?

      # used to hold compiled template methods
      @compiled_method = {}

      # used on 1.9 to set the encoding if it is not set elsewhere (like a magic comment)
      # currently only used if template compiles to ruby
      @default_encoding = @options.delete :default_encoding

      # Resolve the locals contract declared for this template, if any.
      # The :locals_contract option overrides any class-level contract;
      # pass false or nil to disable an inherited contract.
      contract = @options.delete(:locals_contract) { self.class.locals_contract }
      @locals_contract = LocalsContract.new(contract) if contract

      # load template data and prepare (uses binread to avoid encoding issues)
      @reader = block || lambda { |t| read_template_file }
      @data = @reader.call(self)

      if @data.respond_to?(:force_encoding)
        if default_encoding
          @data = @data.dup if @data.frozen?
          @data.force_encoding(default_encoding)
        end

        if !@data.valid_encoding?
          raise Encoding::InvalidByteSequenceError, "#{eval_file} is not valid #{@data.encoding}"
        end
      end

      prepare
    end

    # Render the template in the given scope with the locals specified. If a
    # block is given, it is typically available within the template via
    # +yield+.
    #
    # If the template declares a locals contract, the locals are checked
    # against the contract (and defaults for omitted optional locals are
    # applied) before the template is evaluated.  See LocalsContract.
    def render(scope=nil, locals={}, &block)
      scope ||= Object.new
      locals = apply_locals_contract(locals || {})
      current_template = Thread.current[:tilt_current_template]
      begin
        Thread.current[:tilt_current_template] = self
        evaluate(scope, locals, &block)
      ensure
        Thread.current[:tilt_current_template] = current_template
      end
    end

    # The basename of the template file.
    def basename(suffix='')
      File.basename(file, suffix) if file
    end

    # The template file's basename with all extensions chomped off.
    def name
      basename.split('.', 2).first if basename
    end

    # The filename used in backtraces to describe the template.
    def eval_file
      file || '(__TEMPLATE__)'
    end

    # An empty Hash that the template engine can populate with various
    # metadata.
    def metadata
      if respond_to?(:allows_script?)
        self.class.metadata.merge(:allows_script => allows_script?)
      else
        self.class.metadata
      end
    end

    # Set the prefix to use for compiled paths.
    def compiled_path=(path)
      if path
        # Use expanded paths when loading, since that is helpful
        # for coverage.  Remove any .rb suffix, since that will
        # be added back later.
        path = File.expand_path(path.sub(/\.rb\z/i, ''))
      end
      @compiled_path = path
    end

    protected

    # @!group For template implementations

    # The encoding of the source data. Defaults to the
    # default_encoding-option if present. You may override this method
    # in your template class if you have a better hint of the data's
    # encoding.
    attr_reader :default_encoding

    # Do whatever preparation is necessary to setup the underlying template
    # engine. Called immediately after template data is loaded. Instance
    # variables set in this method are available when #evaluate is called.
    #
    # Subclasses must provide an implementation of this method.
    def prepare
      raise NotImplementedError
    end

    CLASS_METHOD = Kernel.instance_method(:class)
    USE_BIND_CALL = RUBY_VERSION >= '2.7'

    # Execute the compiled template and return the result string. Template
    # evaluation is guaranteed to be performed in the scope object with the
    # locals specified and with support for yielding to the block.
    #
    # This method is only used by source generating templates. Subclasses that
    # override render() may not support all features.
    def evaluate(scope, locals, &block)
      locals_keys = locals.keys
      locals_keys.sort!{|x, y| x.to_s <=> y.to_s}

      case scope
      when Object
        scope_class = Module === scope ? scope : scope.class
      else
        scope_class = USE_BIND_CALL ? CLASS_METHOD.bind_call(scope) : CLASS_METHOD.bind(scope).call
      end
      method = compiled_method(locals_keys, scope_class)

      if USE_BIND_CALL
        method.bind_call(scope, locals, &block)
      else
        method.bind(scope).call(locals, &block)
      end
    end

    # Generates all template source by combining the preamble, template, and
    # postamble and returns a two-tuple of the form: [source, offset], where
    # source is the string containing (Ruby) source code for the template and
    # offset is the integer line offset where line reporting should begin.
    #
    # Template subclasses may override this method when they need complete
    # control over source generation or want to adjust the default line
    # offset. In most cases, overriding the #precompiled_template method is
    # easier and more appropriate.
    def precompiled(local_keys)
      preamble = precompiled_preamble(local_keys)
      template = precompiled_template(local_keys)
      postamble = precompiled_postamble(local_keys)
      source = String.new

      # Ensure that our generated source code has the same encoding as the
      # the source code generated by the template engine.
      if source.respond_to?(:force_encoding)
        template_encoding = extract_encoding(template)

        source.force_encoding(template_encoding)
        template.force_encoding(template_encoding)
      end

      source << preamble << "\n" << template << "\n" << postamble

      [source, preamble.count("\n")+1]
    end

    # A string containing the (Ruby) source code for the template. The
    # default Template#evaluate implementation requires either this
    # method or the #precompiled method be overridden. When defined,
    # the base Template guarantees correct file/line handling, locals
    # support, custom scopes, proper encoding, and support for template
    # compilation.
    def precompiled_template(local_keys)
      raise NotImplementedError
    end

    def precompiled_preamble(local_keys)
      ''
    end

    def precompiled_postamble(local_keys)
      ''
    end

    # !@endgroup

    private

    # Apply the declared locals contract (if any) to the given locals,
    # returning the locals to evaluate the template with.
    def apply_locals_contract(locals)
      if (contract = @locals_contract)
        contract.resolve(locals, self)
      else
        locals
      end
    end

    def read_template_file
      data = File.open(file, 'rb') { |io| io.read }
      if data.respond_to?(:force_encoding)
        # Set it to the default external (without verifying)
        data.force_encoding(Encoding.default_external) if Encoding.default_external
      end
      data
    end

    # The compiled method for the locals keys provided.
    def compiled_method(locals_keys, scope_class=nil)
      LOCK.synchronize do
        @compiled_method[[scope_class, locals_keys]] ||= compile_template_method(locals_keys, scope_class)
      end
    end

    def local_extraction(local_keys)
      local_keys.map do |k|
        if k.to_s =~ /\A[a-z_][a-zA-Z_0-9]*\z/
          "#{k} = locals[#{k.inspect}]"
        else
          raise "invalid locals key: #{k.inspect} (keys must be variable names)"
        end
      end.join("\n")
    end

    def compile_template_method(local_keys, scope_class=nil)
      source, offset = precompiled(local_keys)
      local_code = local_extraction(local_keys)

      method_name = "__tilt_#{Thread.current.object_id.abs}"
      method_source = String.new

      if method_source.respond_to?(:force_encoding)
        method_source.force_encoding(source.encoding)
      end

      if freeze_string_literals?
        method_source << "# frozen-string-literal: true\n"
      end

      # Don't indent method source, to avoid indentation warnings when using compiled paths
      method_source << "::Tilt::TOPOBJECT.class_eval do\ndef #{method_name}(locals)\n#{local_code}\n"

      offset += method_source.count("\n")
      method_source << source
      method_source << "\nend;end;"

      bind_compiled_method(method_source, offset, scope_class, local_keys)
      unbind_compiled_method(method_name)
    end

    def bind_compiled_method(method_source, offset, scope_class, local_keys)
      path = compiled_path
      if path && scope_class.name
        path = path.dup

        if defined?(@compiled_path_counter)
          path << '-' << @compiled_path_counter.succ!
        else
          @compiled_path_counter = "0".dup
        end
        path << ".rb"

        # Wrap method source in a class block for the scope, so constant lookup works
        method_source = "class #{scope_class.name}\n#{method_source}\nend"

        load_compiled_method(path, method_source)
      else
        if path
          warn "compiled_path (#{compiled_path.inspect}) ignored on template with anonymous scope_class (#{scope_class.inspect})"
        end

        eval_compiled_method(method_source, offset, scope_class)
      end
    end

    def eval_compiled_method(method_source, offset, scope_class)
      (scope_class || Object).class_eval(method_source, eval_file, line - offset)
    end

    def load_compiled_method(path, method_source)
      File.binwrite(path, method_source)

      # Use load and not require, so unbind_compiled_method does not
      # break if the same path is used more than once.
      load path
    end

    def unbind_compiled_method(method_name)
      method = TOPOBJECT.instance_method(method_name)
      TOPOBJECT.class_eval { remove_method(method_name) }
      method
    end

    def extract_encoding(script)
      extract_magic_comment(script) || script.encoding
    end

    def extract_magic_comment(script)
      binary(script) do
        script[/\A[ \t]*\#.*coding\s*[=:]\s*([[:alnum:]\-_]+).*$/n, 1]
      end
    end

    def freeze_string_literals?
      false
    end

    def binary(string)
      original_encoding = string.encoding
      string.force_encoding(Encoding::BINARY)
      yield
    ensure
      string.force_encoding(original_encoding)
    end
  end
end
