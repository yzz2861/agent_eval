# frozen_string_literal: false
require_relative 'functions'
require_relative 'xpath_parser'

module REXML
  # Wrapper class.  Use this class to access the XPath functions.
  class XPath
    # A base Hash object, supposing to be used when initializing a
    # default empty namespaces set, but is currently unused.
    # TODO: either set the namespaces=EMPTY_HASH, or deprecate this.
    EMPTY_HASH = {}

    class UndefinedVariable < RuntimeError
      attr_reader :name

      def initialize(name)
        @name = name
        super("Undefined variable: $#{name}")
      end
    end

    # A parsed XPath expression that can be evaluated against many documents.
    # The object itself contains no evaluation state, so the same instance may
    # be shared between threads.  Each evaluation receives its own document,
    # namespace mapping, and variables.
    class Compiled
      def initialize(path=nil, strict: false)
        @options = {
          strict: strict,
        }.freeze
        @path_stack = XPathParser.new(strict: strict).compile(path)
        freeze
      end

      def match(element, namespaces=nil, variables={}, **options)
        validate_arguments(namespaces, variables)
        parser_options = @options.merge(options)
        XPathParser.new(**parser_options, require_variables: true).evaluate(
          @path_stack,
          element,
          namespaces,
          variables
        )
      end

      def first(element, namespaces=nil, variables={}, **options)
        match(element, namespaces, variables, **options).flatten[0]
      end

      def each(element, namespaces=nil, variables={}, **options, &block)
        match(element, namespaces, variables, **options).each(&block)
      end

      private
      def validate_arguments(namespaces, variables)
        unless namespaces.nil? or namespaces.kind_of?(Hash)
          raise "The namespaces argument, if supplied, must be a hash object."
        end
        unless variables.kind_of?(Hash)
          raise "The variables argument, if supplied, must be a hash object."
        end
      end
    end

    # Compiles an XPath expression without evaluating it.  Syntax errors are
    # reported here; errors that depend on evaluation data, such as missing
    # variables, are reported when the returned plan is used.
    def XPath.compile(path=nil, **options)
      Compiled.new(path, **options)
    end

    # Finds and returns the first node that matches the supplied xpath.
    # element::
    #   The context element
    # path::
    #   The xpath to search for.  If not supplied or nil, returns the first
    #   node matching '*'.
    # namespaces::
    #   If supplied, a Hash which defines a namespace mapping.
    # variables::
    #   If supplied, a Hash which maps $variables in the query
    #   to values. This can be used to avoid XPath injection attacks
    #   or to automatically handle escaping string values.
    #
    #  XPath.first( node )
    #  XPath.first( doc, "//b"} )
    #  XPath.first( node, "a/x:b", { "x"=>"http://doofus" } )
    #  XPath.first( node, '/book/publisher/text()=$publisher', {}, {"publisher"=>"O'Reilly"})
    def XPath::first(element, path=nil, namespaces=nil, variables={}, options={})
      raise "The namespaces argument, if supplied, must be a hash object." unless namespaces.nil? or namespaces.kind_of?(Hash)
      raise "The variables argument, if supplied, must be a hash object." unless variables.kind_of?(Hash)
      match(element, path, namespaces, variables, options).flatten[0]
    end

    # Iterates over nodes that match the given path, calling the supplied
    # block with the match.
    # element::
    #   The context element
    # path::
    #   The xpath to search for.  If not supplied or nil, defaults to '*'
    # namespaces::
    #   If supplied, a Hash which defines a namespace mapping
    # variables::
    #   If supplied, a Hash which maps $variables in the query
    #   to values. This can be used to avoid XPath injection attacks
    #   or to automatically handle escaping string values.
    #
    #  XPath.each( node ) { |el| ... }
    #  XPath.each( node, '/*[@attr='v']' ) { |el| ... }
    #  XPath.each( node, 'ancestor::x' ) { |el| ... }
    #  XPath.each( node, '/book/publisher/text()=$publisher', {}, {"publisher"=>"O'Reilly"}) \
    #    {|el| ... }
    def XPath::each(element, path=nil, namespaces=nil, variables={}, options={}, &block)
      raise "The namespaces argument, if supplied, must be a hash object." unless namespaces.nil? or namespaces.kind_of?(Hash)
      raise "The variables argument, if supplied, must be a hash object." unless variables.kind_of?(Hash)
      match(element, path, namespaces, variables, options).each(&block)
    end

    # Returns an array of nodes matching a given XPath.
    def XPath::match(element, path=nil, namespaces=nil, variables={}, options={})
      return path.match(element, namespaces, variables, **options) if path.is_a?(Compiled)
      parser = XPathParser.new(**options)
      parser.namespaces = namespaces
      parser.variables = variables
      path = "*" unless path
      parser.parse(path,element)
    end
  end
end
