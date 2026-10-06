
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
# will not be acted upon. If you need the rules to be applied over and over
# again until the tree reaches a fixpoint (eg. for successive simplification
# of an expression tree), use #apply_until_stable instead of #apply.
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
  # FIXME: Maybe only part of it? Or maybe only include into constructor
  # context?
  include Parslet   
  
  # Raised by #apply_until_stable when the tree does not reach a fixpoint
  # within the configured work limits. Carries enough information to locate
  # the problem: the rule (pattern and block) that fired last and the path
  # from the tree root to the node it fired on. The half-transformed tree is
  # never returned; it is discarded along with the exception.
  #
  class FixpointError < StandardError
    # Pattern of the rule that was applied last before aborting.
    attr_reader :pattern
    # Block of the rule that was applied last before aborting.
    attr_reader :block
    # Path from the tree root to the node the last rule fired on; an array
    # of hash keys and array indices.
    attr_reader :path
    # Number of completed rule-applying passes when the error was raised.
    attr_reader :passes
    # Total number of rule applications when the error was raised.
    attr_reader :applications

    def initialize(reason, pattern, block, path, passes, applications)
      @pattern = pattern
      @block = block
      @path = path
      @passes = passes
      @applications = applications

      location = block && block.source_location
      origin = location ? " (defined at #{location.join(':')})" : ''

      super(
        "#{reason}. Last rule applied: #{pattern.inspect}#{origin}, " +
        "at tree path #{path.inspect} " +
        "(#{passes} passes, #{applications} rule applications so far). " +
        "The partially transformed tree has been discarded."
      )
    end
  end

  class << self
    # FIXME: Only do this for subclasses?
    include Parslet
    
    # Define a rule for the transform subclass. 
    #
    def rule(expression, &block)
      @__transform_rules ||= []
      # Prepend new rules so they have higher precedence than older rules
      @__transform_rules.unshift([Parslet::Pattern.new(expression), block])
    end
    
    # Allows accessing the class' rules
    #
    def rules 
      @__transform_rules ||= []
    end

    def inherited(subclass)
      super
      subclass.instance_variable_set(:@__transform_rules, rules.dup)
    end
  end
  
  def initialize(raise_on_unmatch=false, &block) 
    @raise_on_unmatch = raise_on_unmatch
    @rules = []
    
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
    # Prepend new rules so they have higher precedence than older rules
    @rules.unshift([Parslet::Pattern.new(expression), block])
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
    apply_at(obj, context, [], nil)
  end

  # Applies the transformation rules over and over again until the tree
  # stops changing, ie. until a complete pass over the tree applies not a
  # single rule anymore. When this method returns normally, the returned
  # tree is therefore guaranteed to be a fixpoint of the rule set: no rule
  # matches anywhere in it. In contrast to #apply (a single depth-first,
  # post-order pass), this is the entry point to use for normalisation tasks
  # like constant folding, where one simplification enables the next.
  #
  # Re-matching semantics: within one pass, the result of a replacement is
  # left alone, exactly as in #apply. If any rule fired during a pass, the
  # whole resulting tree is traversed again from the root (depth-first,
  # post-order); nodes created by replacements and the parents of replaced
  # nodes are reconsidered during that next pass.
  #
  # Rule precedence is the same as for #apply, since both draw from #rules:
  # rules inherited from the class (and its ancestors) are tried before
  # rules defined on the instance; within each of those two groups, a rule
  # defined later takes precedence over rules defined earlier.
  #
  # Since rules may oscillate between two tree shapes or grow the tree on
  # every application, termination cannot be guaranteed in general. Two work
  # limits bound the effort:
  #
  # * <tt>:max_passes</tt> - how many passes that applied at least one rule
  #   are tolerated (default: 100)
  # * <tt>:max_applications</tt> - how many rule applications in total are
  #   tolerated (default: 10_000)
  #
  # When a limit is exceeded, a Parslet::Transform::FixpointError is raised
  # that pinpoints the last applied rule and its tree path; the partially
  # transformed tree is discarded instead of being returned as if it were a
  # success value.
  #
  #   transform.apply_until_stable(tree)
  #   transform.apply_until_stable(tree, nil, :max_passes => 10)
  #
  # @param obj PORO ast to transform
  # @param context start context to inject into the bindings.
  # @param options [Hash] work limits :max_passes and :max_applications
  #
  def apply_until_stable(obj, context=nil, options={})
    max_passes = options.fetch(:max_passes, 100)
    max_applications = options.fetch(:max_applications, 10_000)

    passes = 0
    applications = 0
    last_application = nil
    current = obj

    loop do
      applied = false
      observer = lambda do |pattern, block, path|
        applied = true
        applications += 1
        last_application = [pattern, block, path]

        if applications > max_applications
          raise FixpointError.new(
            "Exceeded the limit of #{max_applications} rule applications",
            pattern, block, path, passes, applications)
        end
      end

      current = apply_at(current, context, [], observer)

      # A complete pass without a single rule application proves that no
      # rule matches anywhere in the tree: current is a fixpoint.
      return current unless applied

      passes += 1
      if passes >= max_passes
        pattern, block, path = last_application
        raise FixpointError.new(
          "Exceeded the limit of #{max_passes} passes",
          pattern, block, path, passes, applications)
      end
    end
  end

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
  # ones predefined in a subclass definition. Rules are tried in the order
  # of this list: class level rules (inherited ones included) take
  # precedence over instance level rules; within each level, rules defined
  # later take precedence over rules defined earlier.
  #
  def rules 
    self.class.rules + @rules
  end
  
  # @api private 
  #
  def apply_at(obj, context, path, observer)
    transform_elt(
      case obj
        when Hash
          recurse_hash(obj, context, path, observer)
        when Array
          recurse_array(obj, context, path, observer)
      else
        obj
      end, 
      context,
      path,
      observer
    )
  end

  # @api private 
  #
  def transform_elt(elt, context, path=[], observer=nil) 
    rules.each do |pattern, block|
      if bindings=pattern.match(elt, context)
        observer.call(pattern, block, path) if observer

        # Produces transformed value
        return call_on_match(bindings, block)
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
  def recurse_hash(hsh, ctx, path=[], observer=nil) 
    hsh.inject({}) do |new_hsh, (k,v)|
      new_hsh[k] = apply_at(v, ctx, path + [k], observer)
      new_hsh
    end
  end
  # @api private 
  #
  def recurse_array(ary, ctx, path=[], observer=nil) 
    ary.each_with_index.map do |elt, index|
      apply_at(elt, ctx, path + [index], observer)
    end
  end
end

require 'parslet/context'
