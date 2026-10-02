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
    LazyCandidate = Struct.new(:class_name, :file)

    # @private
    attr_reader :lazy_map, :template_map

    attr_accessor :fallback

    def initialize(source=nil, options=nil, &block)
      if source.is_a?(Hash) && options.nil?
        options = source
        source = nil
      end

      @mutex = Monitor.new
      @template_map = Hash.new
      @lazy_map = Hash.new { |h, k| h[k] = [] }
      @resolved_extensions = Hash.new
      @resolved_candidates = Hash.new
      @loaded_candidates = Hash.new
      @explicit_extensions = Hash.new
      @preloaded_candidates = Hash.new
      @registry_snapshot = (options || {})[:_registry_snapshot]
      @fallback = block || (options || {})[:fallback]

      copy_from(source) if source
    end

    # @private
    def initialize_copy(other)
      @mutex = Monitor.new
      @explicit_extensions = Hash.new
      @loaded_candidates = Hash.new
      @resolved_candidates = Hash.new
      @preloaded_candidates = Hash.new
      @registry_snapshot =
        other.instance_variable_defined?(:@registry_snapshot) &&
        other.instance_variable_get(:@registry_snapshot)
      @fallback = other.fallback
      copy_from(other)
    end

    alias lazy_load_fallback fallback
    alias fallback_policy fallback
    alias lazy_load_fallback= fallback=
    alias fallback_policy= fallback=

    # Sets a custom policy that determines whether Tilt should try the next
    # lazy candidate after a candidate has failed.
    def on_lazy_load_failure(&block)
      @fallback = block
      self
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
        class_name = "Tilt::#{class_name}"
      end

      synchronize do
        updated = @lazy_map.dup
        extensions.each do |ext|
          ext = ext.to_s
          updated[ext] = [[class_name, file]] + @lazy_map[ext]
        end
        @lazy_map = updated
      end
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

      extensions.each do |ext|
        ext = ext.to_s
        synchronize do
          @resolved_extensions.delete(ext)
          @resolved_candidates.delete(ext)
          @explicit_extensions[ext] = true
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

      register(klass, ext, *Array(options[:extra_exts]))
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
      extensions.each do |ext|
        ext = ext.to_s
        synchronize do
          @resolved_extensions.delete(ext)
          @resolved_candidates.delete(ext)
          @explicit_extensions.delete(ext)
          @template_map.delete(ext)
          @lazy_map.delete(ext)
        end
      end

      nil
    end

    # Removes one lazy engine candidate from all extensions or only from the
    # given extensions. Resolved registrations for the same engine are also
    # removed so the remaining candidates can be tried later.
    def disable_candidate(engine, *extensions)
      identifier = engine_identifier(engine)
      target_extensions = extensions.map(&:to_s)

      synchronize do
        target_extensions = @lazy_map.keys if target_extensions.empty?

        target_extensions.each do |ext|
          if @template_map[ext] &&
              (@resolved_candidates[ext].to_a.first == identifier ||
               engine_matches?(engine, identifier, @template_map[ext]))
            @resolved_extensions.delete(ext)
            @explicit_extensions.delete(ext)
            @template_map.delete(ext)
          end

          before = @lazy_map[ext]
          candidates = before.reject { |class_name, _| class_name == identifier }
          next if candidates.length == before.length

          if candidates.empty?
            @lazy_map.delete(ext)
          else
            @lazy_map[ext] = candidates
          end
        end
      end

      nil
    end

    alias disable_engine disable_candidate
    alias unregister_lazy disable_candidate

    # Disables an engine candidate. When given an extension without a matching
    # engine candidate, removes all mappings for that extension.
    def disable(engine, *extensions)
      identifier = engine.respond_to?(:to_str) ? engine.to_str : engine_identifier(engine)

      if extensions.empty? && engine.respond_to?(:to_str) &&
          !candidate?(identifier) && registered?(identifier)
        unregister(identifier)
      else
        disable_candidate(engine, *extensions)
      end
    end

    # Returns the lazy candidates for an extension in priority order. Pass all
    # candidates to replace their order.
    def candidate_order(ext, *engines)
      ext = ext.to_s

      synchronize do
        current = @lazy_map[ext].map { |candidate| candidate.dup }
        return current.map { |candidate| LazyCandidate.new(*candidate) } if engines.empty?

        requested = engines.flatten.map { |engine| engine_identifier(engine) }
        expected = current.map(&:first)

        if requested.sort != expected.sort
          raise ArgumentError, "#{ext.inspect} must be ordered with all candidates: #{expected.inspect}"
        end

        grouped = current.group_by(&:first)
        @lazy_map[ext] = requested.map { |identifier| grouped[identifier].shift.to_a }
        clear_resolved(ext)
        @lazy_map[ext].map { |candidate| LazyCandidate.new(*candidate) }
      end
    end

    alias order candidate_order

    # Moves a lazy engine candidate to the front for all extensions or the
    # given extensions without loading the engine.
    def promote(engine, *extensions)
      identifier = engine_identifier(engine)
      target_extensions = extensions.map(&:to_s)

      synchronize do
        if target_extensions.empty?
          target_extensions = @lazy_map.keys.select do |ext|
            @lazy_map[ext].any? { |class_name, _| class_name == identifier }
          end
        end

        target_extensions.each do |ext|
          matching, remaining = @lazy_map[ext].partition do |class_name, _|
            class_name == identifier
          end

          if matching.empty?
            raise ArgumentError, "#{identifier.inspect} is not registered for #{ext.inspect}"
          end

          @lazy_map[ext] = matching + remaining
          clear_resolved(ext)
        end
      end

      self
    end

    alias prefer_candidate promote

    # Prefers an existing lazy candidate without loading it, or eagerly
    # registers the engine if it is not already a lazy candidate.
    def prefer(engine, *extensions)
      identifier = engine_identifier(engine)
      target_extensions = extensions.map(&:to_s)

      synchronize do
        target_extensions = @lazy_map.keys if target_extensions.empty?
        all_candidates = target_extensions.all? do |ext|
          @lazy_map[ext].any? { |class_name, _| class_name == identifier }
        end

        if all_candidates && !target_extensions.empty?
          promote(engine, *target_extensions)
        else
          register(engine, *extensions)
        end
      end
    end

    # Returns a defensive copy of the lazy candidates for an extension.
    def candidates(ext)
      synchronize do
        @lazy_map[ext.to_s].map { |candidate| LazyCandidate.new(*candidate) }
      end
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
      @template_map.has_key?(ext.downcase) or lazy?(ext)
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
      template_map.each do |ext, klass|
        res << ext if template_class == klass
      end
      lazy_map.each do |ext, choices|
        res << ext if choices.any? { |klass, file| template_class.to_s == klass }
      end
      res.uniq
    end

    private

    def synchronize(&block)
      @mutex.synchronize(&block)
    end

    def copy_from(source)
      return unless source

      copy = proc do
        @explicit_extensions =
          if source.respond_to?(:explicit_extensions, true)
            source.send(:explicit_extensions).dup
          else
            source.template_map.keys.each_with_object({}) { |ext, map| map[ext] = true }
          end
        if @registry_snapshot
          @template_map = source.template_map.select do |ext, _|
            @explicit_extensions.has_key?(ext)
          end
        else
          @template_map = source.template_map.dup
        end
        @lazy_map = Hash.new { |h, k| h[k] = [] }
        source.lazy_map.each do |ext, candidates|
          @lazy_map[ext] = candidates.map { |candidate| candidate.dup }
        end
        if @registry_snapshot
          @preloaded_candidates =
            if source.instance_variable_get(:@registry_snapshot)
              preloaded_candidates_from(source)
            else
              snapshot_defined_candidates(source)
            end
        else
          @resolved_extensions = source.send(:resolved_extensions).dup
          @loaded_candidates = source.send(:loaded_candidates).dup
          @resolved_candidates = source.send(:resolved_candidates).dup
        end
      end

      if source.respond_to?(:synchronize, true)
        source.send(:synchronize, &copy)
      else
        copy.call
      end
    end

    attr_reader :resolved_extensions,
                :resolved_candidates,
                :explicit_extensions,
                :loaded_candidates,
                :preloaded_candidates
    private :resolved_extensions,
            :resolved_candidates,
            :explicit_extensions,
            :loaded_candidates,
            :preloaded_candidates

    def snapshot_defined_candidates(source)
      preloaded = {}
      source.lazy_map.each do |ext, candidates|
        candidates.each do |class_name, file|
          resolved_name = source.send(:resolved_candidates)[ext]
          if resolved_name.respond_to?(:class_name)
            resolved_name = resolved_name.class_name
          elsif resolved_name.is_a?(Array)
            resolved_name = resolved_name.first
          end
          next if resolved_name == class_name
          preloaded[[class_name, file]] = true if constant_defined?(class_name)
        end
      end
      preloaded
    end

    def preloaded_candidates_from(source)
      preloaded = source.send(:preloaded_candidates).dup
      source.send(:resolved_candidates).each_value do |candidate|
        preloaded.delete([candidate.class_name, candidate.file])
      end
      preloaded
    end

    def engine_identifier(engine)
      if engine.respond_to?(:to_str)
        engine.to_str
      elsif engine.is_a?(Symbol)
        "Tilt::#{engine}"
      elsif engine.respond_to?(:name) && engine.name
        engine.name
      else
        engine.to_s
      end
    end

    def engine_matches?(engine, identifier, template_class)
      template_class == engine ||
        (template_class.respond_to?(:name) && template_class.name == identifier)
    end

    def candidate?(identifier)
      @lazy_map.values.any? do |candidates|
        candidates.any? { |class_name, _| class_name == identifier }
      end
    end

    def clear_resolved(ext)
      if @resolved_extensions.delete(ext)
        @resolved_candidates.delete(ext)
        @template_map.delete(ext)
      end
    end

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
      @template_map[ext] || lazy_load(ext)
    end

    def lazy_load(pattern)
      return unless @lazy_map.has_key?(pattern)
      failure = nil

      synchronize do
        resolved = @template_map[pattern]
        return resolved if resolved

        choices = @lazy_map[pattern]
        return if choices.empty?

        # Check if a template class is already present
        choices.each do |class_name, file|
          next if @registry_snapshot &&
            !@preloaded_candidates.has_key?([class_name, file]) &&
            !@loaded_candidates.has_key?([class_name, file])
          template_class = constant_defined?(class_name)
          if template_class
            commit_resolved(template_class, pattern)
            return template_class
          end
        end

        choices.each do |class_name, file|
          candidate = LazyCandidate.new(class_name, file)

          begin
            require file
            # It's safe to eval() here because constant_defined? will
            # raise NameError on invalid constant names
            template_class = eval(class_name)
          rescue LoadError, StandardError => error
            if fallback_allowed?(error, candidate)
              failure ||= error
            else
              raise
            end
          else
            @loaded_candidates[[class_name, file]] = true
            commit_resolved_candidate(template_class, candidate, pattern)
            return template_class
          end
        end
      end

      raise failure if failure
    end

    def commit_resolved(template_class, ext)
      @resolved_extensions[ext] = true
      @template_map[ext] = template_class
    end

    def commit_resolved_candidate(template_class, candidate, ext)
      @resolved_candidates[ext] = candidate
      commit_resolved(template_class, ext)
    end

    def fallback_allowed?(error, candidate)
      case @fallback
      when nil, true, :fallback, :load_error
        error.is_a?(LoadError)
      when false, :raise, :none
        false
      else
        if @fallback.respond_to?(:call)
          call_fallback_policy(error, candidate)
        else
          error.is_a?(LoadError)
        end
      end
    end

    def call_fallback_policy(error, candidate)
      call_method = @fallback.method(:call)
      parameters = call_method.parameters
      arity = parameters.count { |type, _| type == :req || type == :opt }
      arity = 3 if arity.zero? && parameters.any? { |type, _| type == :rest }

      case arity
      when 1
        @fallback.call(error)
      when 2
        @fallback.call(error, candidate)
      when 0
        @fallback.call
      else
        @fallback.call(error, candidate.class_name, candidate.file)
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
  end
end
