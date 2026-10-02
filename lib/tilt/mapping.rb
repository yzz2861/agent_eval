require 'monitor'
require_relative 'pipeline'

module Tilt
  # Tilt::Mapping associates file extensions with template implementations.
  #
  #     mapping = Tilt::Mapping.new
  #     mapping.register(Tilt::RDocTemplate, 'rdoc')
  #     mapping['index.rdoc'] # => Tilt::RDocTemplate
  #     mapping.new('index.rdoc').render
  #
  # You can use {#register} to register a template class by file
  # extension, {#registered?} to see if a file extension is mapped,
  # {#[]} to lookup template classes, and {#new} to instantiate template
  # objects.
  #
  # Mapping also supports *lazy* template implementations. Note that regularly
  # registered template implementations *always* have preference over lazily
  # registered template implementations. You should use {#register} if you
  # depend on a specific template implementation and {#register_lazy} if there
  # are multiple alternatives.
  #
  #     mapping = Tilt::Mapping.new
  #     mapping.register_lazy('RDiscount::Template', 'rdiscount/template', 'md')
  #     mapping['index.md']
  #     # => RDiscount::Template
  #
  # {#register_lazy} takes a class name, a filename, and a list of file
  # extensions. When you try to lookup a template name that matches the
  # file extension, Tilt will automatically try to require the filename and
  # constantize the class name.
  #
  # Unlike {#register}, there can be multiple template implementations
  # registered lazily to the same file extension. Tilt will attempt to load the
  # template implementations in order (registered *last* would be tried first),
  # returning the first which doesn't raise LoadError.
  #
  # If all of the registered template implementations fails, Tilt will raise
  # the exception of the first, since that was the most preferred one.
  #
  #     mapping = Tilt::Mapping.new
  #     mapping.register_lazy('Bluecloth::Template', 'bluecloth/template', 'md')
  #     mapping.register_lazy('RDiscount::Template', 'rdiscount/template', 'md')
  #     mapping['index.md']
  #     # => RDiscount::Template
  #
  # In the previous example we say that RDiscount has a *higher priority* than
  # BlueCloth. Tilt will first try to `require "rdiscount/template"`, falling
  # back to `require "bluecloth/template"`. If none of these are successful,
  # the first error will be raised.
  class Mapping
    # @private
    attr_reader :lazy_map, :template_map

    # Controls whether a lazy candidate failure allows Tilt to try the
    # next candidate. Built-in values are :load_error, :raise, :any, and
    # any callable object.
    attr_reader :fallback_policy

    # Creates a new mapping. When +source+ is another mapping, an independent
    # snapshot of its current configuration is used as the initial state.
    def initialize(source=nil, options=nil)
      @template_map = Hash.new
      @lazy_map = Hash.new { |h, k| h[k] = [] }
      @resolved_map = Hash.new
      @lock = Monitor.new

      if source.is_a?(Hash)
        options = source
        source = nil
      end
      options ||= {}

      @strict_candidate_order = options.fetch(:strict_candidate_order, !source.nil?)
      policy = options.key?(:fallback_policy) ? options[:fallback_policy] : options[:fallback]
      self.fallback_policy = policy.nil? && !options.key?(:fallback) ? :load_error : policy
      copy_from(source) if source

      yield self if block_given?
    end

    # @private
    def initialize_copy(other)
      copy_from(other)
      @fallback_policy = other.fallback_policy
      @strict_candidate_order = true
      @lock = Monitor.new
    end

    # @return [Tilt::Mapping] an independent snapshot of the mapping
    alias snapshot dup

    # @return [Boolean] whether lazy candidates are attempted in this
    # mapping's order before globally loaded lower-priority candidates
    def strict_candidate_order?
      @strict_candidate_order
    end

    def fallback_policy=(policy)
      valid = case policy
              when Symbol
                [:load_error, :default, :raise, :never, :any, :always].include?(policy)
              when true, false, nil
                true
              else
                policy.respond_to?(:call)
              end

      unless valid
        raise ArgumentError, "invalid lazy load fallback policy: #{policy.inspect}"
      end

      @fallback_policy = policy
    end

    # Registers a lazy template implementation by file extension. You
    # can have multiple lazy template implementations defined on the
    # same file extension, in which case the template implementation
    # defined *last* will be attempted loaded *first*.
    #
    # @param class_name [String] Class name of a template class.
    # @param file [String] Filename where the template class is defined.
    # @param extensions [Array<String>] List of extensions.
    # @return [void]
    #
    # @example
    #   mapping.register_lazy 'MyEngine::Template', 'my_engine/template',  'mt'
    #
    #   defined?(MyEngine::Template) # => false
    #   mapping['index.mt'] # => MyEngine::Template
    #   defined?(MyEngine::Template) # => true
    def register_lazy(class_name, file, *extensions)
      # Internal API
      if class_name.is_a?(Symbol)
        Tilt.autoload class_name, file
      end

      class_name = lazy_class_name(class_name)
      extensions = extensions.map { |ext| ext.to_s }

      synchronize do
        extensions.each do |ext|
          choices = @lazy_map[ext]
          choices.delete_if { |name, _| name == class_name }
          choices.unshift([class_name, file])
          clear_resolved(ext)
        end
      end
      nil
    end

    # Registers a template implementation by file extension. There can only be
    # one template implementation per file extension, and this method will
    # override any existing mapping.
    #
    # @param template_class
    # @param extensions [Array<String>] List of extensions.
    # @return [void]
    # 
    # @example
    #   mapping.register MyEngine::Template, 'mt'
    #   mapping['index.mt'] # => MyEngine::Template
    def register(template_class, *extensions)
      if template_class.respond_to?(:to_str)
        # Support register(ext, template_class) too
        extensions, template_class = [template_class], extensions[0]
      end

      extensions = extensions.map { |ext| ext.to_s }

      synchronize do
        extensions.each do |ext|
          @resolved_map.delete(ext)
          @template_map[ext] = template_class
        end
      end
    end

    # Register a new template class using the given extension that
    # represents a pipeline of multiple existing template, where the
    # output from the previous template is used as input to the next
    # template.
    #
    # This will register a template class that processes the input
    # with the *erb* template processor, and takes the output of
    # that and feeds it to the *scss* template processor, returning
    # the output of the *scss* template processor as the result of
    # the pipeline.
    #
    # @param ext [String] Primary extension to register
    # @option :templates [Array<String>] Extensions of templates
    #         to execute in order (defaults to the ext.split('.').reverse)
    # @option :extra_exts [Array<String>] Additional extensions to register
    # @option String [Hash] Options hash for individual template in the
    #         pipeline (key is extension).
    # @return [void]
    #
    # @example
    #   mapping.register_pipeline('scss.erb')
    #   mapping.register_pipeline('scss.erb', 'erb'=>{:outvar=>'@foo'})
    #   mapping.register_pipeline('scsserb', :extra_exts => 'scss.erb',
    #                             :templates=>['erb', 'scss'])
    def register_pipeline(ext, options={})
      templates = options[:templates] || ext.split('.').reverse
      templates = templates.map{|t| [self[t], options[t] || {}]}

      klass = Class.new(Pipeline)
      klass.send(:const_set, :TEMPLATES, templates)

      synchronize do
        register(klass, ext, *Array(options[:extra_exts]))
      end
      klass
    end

    # Unregisters an extension. This removes the both normal registrations
    # and lazy registrations.
    #
    # @param extensions [Array<String>] List of extensions.
    # @return nil
    #
    # @example
    #   mapping.register MyEngine::Template, 'mt'
    #   mapping['index.mt'] # => MyEngine::Template
    #   mapping.unregister('mt')
    #   mapping['index.mt'] # => nil
    def unregister(*extensions)
      extensions = extensions.map { |ext| ext.to_s }

      synchronize do
        extensions.each do |ext|
          @template_map.delete(ext)
          @lazy_map.delete(ext)
          @resolved_map.delete(ext)
        end
      end

      nil
    end

    # Moves an existing lazy candidate to the front of the candidate list for
    # each given extension.
    #
    # @param class_name [String, Symbol] Lazy candidate class name.
    # @param extensions [Array<String>] Extensions to update.
    def prefer_lazy(class_name, *extensions)
      class_name = lazy_class_name(class_name)
      extensions = extensions.map { |ext| ext.to_s }

      synchronize do
        assert_lazy_candidate!(class_name, extensions)

        extensions.each do |ext|
          choices = @lazy_map[ext]
          index = choices.index { |name, _| name == class_name }
          choices.unshift(choices.delete_at(index))
          clear_resolved(ext)
        end
      end
      nil
    end
    alias prioritize_lazy prefer_lazy

    # Removes a lazy candidate for each given extension. With no candidate,
    # removes all lazy candidates but keeps eager registrations.
    #
    # @param class_name [String, Symbol, nil] Lazy candidate class name.
    # @param extensions [Array<String>] Extensions to update.
    def unregister_lazy(class_name=nil, *extensions)
      if class_name && extensions.empty?
        extensions = [class_name]
        class_name = nil
      end

      extensions = extensions.map { |ext| ext.to_s }
      raise ArgumentError, "at least one extension is required" if extensions.empty?

      synchronize do
        if class_name
          class_name = lazy_class_name(class_name)
          assert_lazy_candidate!(class_name, extensions)

          extensions.each do |ext|
            @lazy_map[ext].delete_if { |name, _| name == class_name }
            clear_resolved(ext) if resolved_for?(ext, class_name)
            @lazy_map.delete(ext) if @lazy_map[ext].empty?
          end
        else
          extensions.each do |ext|
            @lazy_map.delete(ext)
            clear_resolved(ext)
          end
        end
      end
      nil
    end
    alias disable_lazy unregister_lazy

    # Orders the given lazy candidates at the front of an extension. Remaining
    # candidates keep their current relative order.
    #
    # @param ext [String] Extension to update.
    # @param class_names [Array<String, Symbol>] Candidate class names.
    def order_lazy(ext, *class_names)
      ext = ext.to_s
      class_names = class_names.map { |name| lazy_class_name(name) }
      raise ArgumentError, "at least one candidate is required" if class_names.empty?
      raise ArgumentError, "candidates must be unique" if class_names.uniq.length != class_names.length

      synchronize do
        choices = @lazy_map[ext]
        available = choices.each_with_object({}) { |candidate, hash| hash[candidate[0]] ||= candidate }
        missing = class_names.reject { |name| available.key?(name) }
        unless missing.empty?
          raise ArgumentError, "lazy candidate not registered for #{ext}: #{missing.join(', ')}"
        end

        ordered = class_names.map { |name| available[name] }
        remaining = choices.reject { |name, _| class_names.include?(name) }
        @lazy_map[ext] = ordered + remaining
        clear_resolved(ext)
      end
      nil
    end

    # Checks if a file extension is registered (either eagerly or
    # lazily) in this mapping.
    #
    # @param ext [String] File extension.
    #
    # @example
    #   mapping.registered?('erb')  # => true
    #   mapping.registered?('nope') # => false
    def registered?(ext)
      synchronize do
        @template_map.has_key?(ext.downcase) or lazy?(ext)
      end
    end

    # Instantiates a new template class based on the file.
    #
    # @raise [RuntimeError] if there is no template class registered for the
    #   file name.
    #
    # @example
    #   mapping.new('index.mt') # => instance of MyEngine::Template
    #
    # @see Tilt::Template.new
    def new(file, line=nil, options={}, &block)
      if template_class = self[file]
        template_class.new(file, line, options, &block)
      else
        fail "No template engine registered for #{File.basename(file)}"
      end
    end

    # Looks up a template class based on file name and/or extension.
    #
    # @example
    #   mapping['views/hello.erb'] # => Tilt::ERBTemplate
    #   mapping['hello.erb']       # => Tilt::ERBTemplate
    #   mapping['erb']             # => Tilt::ERBTemplate
    #
    # @return [template class]
    def [](file)
      _, ext = split(file)
      ext && lookup(ext)
    end

    alias template_for []

    # Looks up a list of template classes based on file name. If the file name
    # has multiple extensions, it will return all template classes matching the
    # extensions from the end.
    #
    # @example
    #   mapping.templates_for('views/index.haml.erb')
    #   # => [Tilt::ERBTemplate, Tilt::HamlTemplate]
    #
    # @return [Array<template class>]
    def templates_for(file)
      templates = []

      while true
        prefix, ext = split(file)
        break unless ext
        templates << lookup(ext)
        file = prefix
      end

      templates
    end

    # Finds the extensions the template class has been registered under.
    # @param [template class] template_class
    def extensions_for(template_class)
      res = []
      synchronize do
        template_map.each do |ext, klass|
          res << ext if template_class == klass
        end
        lazy_map.each do |ext, choices|
          res << ext if choices.any? { |klass, file| template_class.to_s == klass }
        end
      end
      res.uniq
    end

    private

    def lazy?(ext)
      ext = ext.downcase
      @lazy_map.has_key?(ext) && !@lazy_map[ext].empty?
    end

    def split(file)
      pattern = file.to_s.downcase
      full_pattern = pattern.dup

      until registered?(pattern)
        return if pattern.empty?
        pattern = File.basename(pattern)
        pattern.sub!(/^[^.]*\.?/, '')
      end

      prefix_size = full_pattern.size - pattern.size
      [full_pattern[0,prefix_size-1], pattern]
    end

    def lookup(ext)
      synchronize do
        @template_map[ext] || lazy_load(ext)
      end
    end

    def lazy_load(pattern)
      synchronize do
        return unless @lazy_map.has_key?(pattern)

        choices = @lazy_map[pattern].map(&:dup)
        failures = []

        unless strict_candidate_order?
          # Check if a template class is already present
          choices.each do |class_name, file|
            template_class = constant_defined?(class_name)
            if template_class
              register_resolved(template_class, pattern)
              return template_class
            end
          end
        end

        # Load in order
        choices.each do |class_name, file|
          begin
            if strict_candidate_order?
              template_class = constant_defined?(class_name)
              if template_class
                register_resolved(template_class, pattern)
                return template_class
              end
            end

            require file
            # It's safe to eval() here because constant_defined? will
            # raise NameError on invalid constant names
            template_class = eval(class_name)
          rescue LoadError, StandardError => error
            if lazy_load_fallback?(error, class_name, file, pattern)
              failures << error
            else
              raise
            end
          else
            register_resolved(template_class, pattern)
            return template_class
          end
        end

        raise failures.first unless failures.empty?
      end
    end

    # The proper behavior (in MRI) for autoload? is to
    # return `false` when the constant/file has been
    # explicitly required.
    #
    # However, in JRuby it returns `true` even after it's
    # been required. In that case it turns out that `defined?`
    # returns `"constant"` if it exists and `nil` when it doesn't.
    # This is actually a second bug: `defined?` should resolve
    # autoload (aka. actually try to require the file).
    #
    # We use the second bug in order to resolve the first bug.

    def constant_defined?(name)
      name.split('::').inject(Object) do |scope, n|
        return false if scope.autoload?(n) || !scope.const_defined?(n)
        scope.const_get(n)
      end
    end

    def lazy_class_name(class_name)
      class_name.is_a?(Symbol) ? "Tilt::#{class_name}" : class_name.to_s
    end

    def register_resolved(template_class, ext)
      @resolved_map[ext] = true
      @template_map[ext] = template_class
    end

    def clear_resolved(ext)
      return unless @resolved_map.delete(ext)
      @template_map.delete(ext)
    end

    def resolved_for?(ext, class_name)
      @resolved_map.key?(ext) && @template_map[ext].to_s == class_name
    end

    def assert_lazy_candidate!(class_name, extensions)
      missing = extensions.reject do |ext|
        @lazy_map[ext].any? { |name, _| name == class_name }
      end

      unless missing.empty?
        raise ArgumentError, "lazy candidate #{class_name} not registered for #{missing.join(', ')}"
      end
    end

    def lazy_load_fallback?(error, class_name, file, pattern)
      case fallback_policy
      when :load_error, :default, nil
        error.is_a?(LoadError)
      when :raise, :never, false
        false
      when :any, :always, true
        true
      else
        if fallback_policy.respond_to?(:call)
          !!call_fallback_policy(error, class_name, file, pattern)
        else
          raise ArgumentError, "invalid lazy load fallback policy: #{fallback_policy.inspect}"
        end
      end
    end

    def call_fallback_policy(error, class_name, file, pattern)
      args = [error, class_name, file, pattern]
      arity = fallback_policy.respond_to?(:arity) ? fallback_policy.arity : 4
      fallback_policy.call(*(arity >= 0 ? args[0, arity] : args))
    end

    def copy_from(other)
      raise ArgumentError, "expected a Tilt::Mapping" unless other.is_a?(Mapping)

      other.synchronize do
        @template_map = other.template_map.dup
        @resolved_map = Hash.new
        other.template_map.each_key do |ext|
          @template_map.delete(ext) if other.resolved?(ext)
        end
        @lazy_map = Hash.new(other.lazy_map.default_proc)
        other.lazy_map.each do |ext, choices|
          @lazy_map[ext] = choices.map(&:dup)
        end
      end
    end

    def synchronize(&block)
      @lock.synchronize(&block)
    end
    protected :synchronize

    def resolved?(ext)
      @resolved_map.key?(ext)
    end
    protected :resolved?
  end
end
