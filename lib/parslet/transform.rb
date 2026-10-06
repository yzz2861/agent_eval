
require 'parslet/pattern'

# Transforms an expression tree into something else. The transformation
# performs a depth-first, post-order traversal of the expression tree. During
# that traversal, each time a rule matches a node, the node is replaced by the
# result of the block associated to the rule. Otherwise the node is accepted
# as is into the result tree.
#
# This is almost what you would generally do with a tree visitor, except that
# you can match several levels of the tree at once. 
#
# As a consequence of this, the resulting tree will contain pieces of the
# original tree and new pieces. Most likely, you will want to transform the
# original tree wholly, so this isn't a problem.
#
# You will not be able to create a loop, given that each node will be replaced
# only once and then left alone. This means that the results of a replacement
# will not be acted upon. 
#
# Example: 
#
#   class Example < Parslet::Transform
#     rule(:string => simple(:x)) {  # (1)
#       StringLiteral.new(x)
#     }
#   end
#
# A tree transform (Parslet::Transform) is defined by a set of rules. Each
# rule can be defined by calling #rule with the pattern as argument. The block
# given will be called every time the rule matches somewhere in the tree given
# to #apply. It is passed a Hash containing all the variable bindings of this
# pattern match. 
#   
# In the above example, (1) illustrates a simple matching rule. 
#
# Let's say you want to parse matching parentheses and distill a maximum nest
# depth. You would probably write a parser like the one in example/parens.rb;
# here's the relevant part: 
#
#   rule(:balanced) {
#     str('(').as(:l) >> balanced.maybe.as(:m) >> str(')').as(:r)
#   }
#
# If you now apply this to a string like '(())', you get a intermediate parse
# tree that looks like this: 
#
#   {
#     l: '(', 
#     m: {
#       l: '(', 
#       m: nil, 
#       r: ')' 
#     }, 
#     r: ')' 
#   }
#
# This parse tree is good for debugging, but what we would really like to have
# is just the nesting depth. This transformation rule will produce that: 
#
#   rule(:l => '(', :m => simple(:x), :r => ')') { 
#     # innermost :m will contain nil
#     x.nil? ? 1 : x+1
#   }
#
# = Usage patterns
#
# There are four ways of using this class. The first one is very much
# recommended, followed by the second one for generality. The other ones are
# omitted here. 
#
# Recommended usage is as follows: 
#
#   class MyTransformator < Parslet::Transform
#     rule(...) { ... }
#     rule(...) { ... }
#     # ...
#   end
#   MyTransformator.new.apply(tree)
#
# Alternatively, you can use the Transform class as follows: 
#
#   transform = Parslet::Transform.new do
#     rule(...) { ... }
#   end
#   transform.apply(tree)
#
# = Execution context
#
# The execution context of action blocks differs depending on the arity of 
# said blocks. This can be confusing. It is however somewhat intentional. You 
# should not create fat Transform descendants containing a lot of helper methods, 
# instead keep your AST class construction in global scope or make it available
# through a factory. The following piece of code illustrates usage of global
# scope: 
#
#   transform = Parslet::Transform.new do
#     rule(...) { AstNode.new(a_variable) }
#     rule(...) { Ast.node(a_variable) } # modules are nice
#   end
#   transform.apply(tree)
#
# And here's how you would use a class builder (a factory):
#
#   transform = Parslet::Transform.new do
#     rule(...) { builder.add_node(a_variable) }
#     rule(...) { |d| d[:builder].add_node(d[:a_variable]) }
#   end
#   transform.apply(tree, :builder => Builder.new)
#
# As you can see, Transform allows you to inject local context for your rule
# action blocks to use. 
#
class Parslet::Transform
  class RepeatedTransformLimit < StandardError
    attr_reader :rule, :path, :pass, :transformations, :max_transformations

    def initialize(rule:, path:, pass:, transformations:, max_transformations:)
      @rule = rule
      @path = path
      @pass = pass
      @transformations = transformations
      @max_transformations = max_transformations

      location = rule[:source] || "unknown source"
      super(
        "Repeated transformation stopped after #{transformations} transformation(s); " \
        "rule ##{rule[:index]} from #{rule[:origin]} (#{location}) matched again at " \
        "#{path.inspect} during pass ##{pass}. The limit is #{max_transformations}."
      )
    end
  end

  RuleDefinition = Struct.new(
    :pattern, :block, :expression, :source, :origin
  )

  class RepeatedTransformState
    attr_reader :matched_count, :transformations, :pass, :max_transformations

    def initialize(max_transformations, pass, transformations=0)
      @max_transformations = max_transformations
      @pass = pass
      @transformations = transformations
      @matched_count = 0
    end

    def limit_reached?
      @transformations >= @max_transformations
    end

    def record
      @matched_count += 1
      @transformations += 1
    end
  end

  # FIXME: Maybe only part of it? Or maybe only include into constructor
  # context?
  include Parslet   
  
  class << self
    # FIXME: Only do this for subclasses?
    include Parslet
    
    # Define a rule for the transform subclass. 
    #
    def rule(expression, &block)
      definition = RuleDefinition.new(
        Parslet::Pattern.new(expression),
        block,
        expression,
        caller_locations(1, 1).first,
        self
      )
      rule_definitions.unshift(definition)
    end
    
    # Allows accessing the class' rules
    #
    def rule_definitions
      @__transform_rule_definitions ||= []
    end

    def rules
      rule_definitions.map { |definition| [definition.pattern, definition.block] }
    end

    def inherited(subclass)
      super
      subclass.instance_variable_set(
        :@__transform_rule_definitions,
        rule_definitions.dup
      )
    end
  end
  
  def initialize(raise_on_unmatch=false, &block) 
    @raise_on_unmatch = raise_on_unmatch
    @rule_definitions = []
    
    if block
      instance_eval(&block)
    end
  end
  
  # Defines a rule to be applied whenever apply is called on a tree. A rule
  # is composed of two parts: 
  # 
  # * an *expression pattern*
  # * a *transformation block*
  #
  def rule(expression, &block)
    definition = RuleDefinition.new(
      Parslet::Pattern.new(expression),
      block,
      expression,
      caller_locations(1, 1).first,
      :instance
    )
    @rule_definitions.unshift(definition)
  end
  
  # Applies the transformation to a tree that is generated by Parslet::Parser
  # or a simple parslet. Transformation will proceed down the tree, replacing
  # parts/all of it with new objects. The resulting object will be returned. 
  #
  # Using the context parameter, you can inject bindings for the transformation.
  # This can be used to allow access to the outside world from transform blocks,
  # like so:
  # 
  #   document = # some class that you act on
  #   transform.apply(tree, document: document)
  #   
  # The above will make document available to all your action blocks: 
  #
  #   # Variant A
  #   rule(...) { document.foo(bar) }
  #   # Variant B
  #   rule(...) { |d| d[:document].foo(d[:bar]) }
  #
  # @param obj PORO ast to transform
  # @param context start context to inject into the bindings. 
  #
  def apply(obj, context=nil)
    apply_single_pass(obj, context, nil)
  end

  # @api private
  #
  def apply_single_pass(obj, context, state, path=[])
    transform_element(
      case obj
        when Hash
          recurse_hash(obj, context, path, state)
        when Array
          recurse_array(obj, context, path, state)
      else
        obj
      end, 
      context,
      path,
      state
    )
  end

  # Repeatedly runs the same depth-first, post-order traversal performed by
  # #apply until a complete pass matches no rule. The result of a rule is not
  # matched again during the pass that created it. On the next pass, however,
  # the traversal starts at the root again, so both replacement nodes and the
  # parents produced by a replacement become eligible for all rules. Existing
  # parents still observe child replacements within their own single pass, as
  # they do in #apply.
  #
  # Rule precedence within every pass is the same as for #apply: rules added
  # to an instance take precedence over class rules; rules defined directly by
  # a subclass take precedence over rules inherited from its ancestors. Newer
  # rules precede older rules in the same scope.
  #
  # A successful return means an additional complete verification pass found
  # no applicable rule. If rules keep changing the tree, either by alternating
  # between forms or adding nodes, the method raises RepeatedTransformLimit
  # after +max_transformations+ successful rule applications. The exception
  # identifies the next rule that would have run and its tree path, so the
  # unfinished tree is never returned as a successful result.
  #
  # @param obj PORO ast to transform
  # @param context start context to inject into the bindings
  # @param options [Hash] transformation options
  # @option options [Integer] :max_transformations (1000) maximum rule
  #   applications
  #
  def apply_repeatedly(obj, context=nil, options=nil)
    options ||= {}
    unless options.is_a?(Hash)
      raise ArgumentError, "options must be a Hash"
    end

    max_transformations ||= options.fetch(:max_transformations, 1000)
    unless max_transformations.is_a?(Integer) && max_transformations >= 0
      raise ArgumentError, "max_transformations must be a non-negative Integer"
    end

    current = obj
    total_transformations = 0
    pass = 0

    loop do
      pass += 1
      state = RepeatedTransformState.new(
        max_transformations,
        pass,
        total_transformations
      )
      current = apply_single_pass(current, context, state)
      total_transformations = state.transformations

      return current if state.matched_count.zero?
    end
  end

  alias apply_until_fixpoint apply_repeatedly
  
  # Executes the block on the bindings obtained by Pattern#match, if such a match
  # can be made. Depending on the arity of the given block, it is called in 
  # one of two environments: the current one or a clean toplevel environment.
  #
  # If you would like the current environment preserved, please use the 
  # arity 1 variant of the block. Alternatively, you can inject a context object
  # and call methods on it (think :ctx => self).
  #
  #   # the local variable a is simulated
  #   t.call_on_match(:a => :b) { a } 
  #   # no change of environment here
  #   t.call_on_match(:a => :b) { |d| d[:a] }
  #
  def call_on_match(bindings, block)
    if block
      if block.arity == 1
        return block.call(bindings)
      else
        context = Context.new(bindings)
        return context.instance_eval(&block)
      end
    end
  end
  
  # Allow easy access to all rules, the ones defined in the instance and the 
  # ones predefined in a subclass definition. 
  #
  def rule_definitions
    @rule_definitions + self.class.rule_definitions
  end

  def rules 
    rule_definitions.map { |definition| [definition.pattern, definition.block] }
  end

  # @api private 
  #
  def transform_element(elt, context, path, state)
    rule_definitions.each_with_index do |definition, rule_index|
      if bindings=definition.pattern.match(elt, context)
        if state && state.limit_reached?
          raise RepeatedTransformLimit.new(
            rule: rule_description(definition, rule_index),
            path: path.dup,
            pass: state.pass,
            transformations: state.transformations,
            max_transformations: state.max_transformations
          )
        end

        # Produces transformed value
        result = call_on_match(bindings, definition.block)

        state.record if state

        return result
      end
    end
    
    # No rule matched - element is not transformed
    if @raise_on_unmatch && elt.is_a?(Hash)
      elt_types = elt.map do |key, value|
        [ key, value.class ]
      end.to_h
      raise NotImplementedError, "Failed to match `#{elt_types.inspect}`"
    else
      return elt
    end
  end

  # @api private 
  #
  def recurse_hash(hsh, ctx, path, state)
    hsh.inject({}) do |new_hsh, (k,v)|
      new_hsh[k] = apply_single_pass(v, ctx, state, path + [k])
      new_hsh
    end
  end
  # @api private 
  #
  def recurse_array(ary, ctx, path, state)
    ary.each_with_index.map do |elt, index|
      apply_single_pass(elt, ctx, state, path + [index])
    end
  end

  # @api private
  #
  def rule_description(definition, index)
    origin = definition.origin
    origin = origin.name || origin.inspect if origin.is_a?(Class)

    {
      index: index,
      origin: origin,
      source: definition.source && definition.source.to_s,
      expression: definition.expression.inspect
    }
  end
end

require 'parslet/context'
