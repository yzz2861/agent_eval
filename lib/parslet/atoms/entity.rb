# This wraps pieces of parslet definition and gives them a name. The wrapped
# piece is lazily evaluated and cached. This has two purposes: 
#     
# * Avoid infinite recursion during evaluation of the definition
# * Be able to print things by their name, not by their sometimes
#   complicated content.
#
# Rules declared with <code>left_recursive: true</code> use the parsing
# context's seeded packrat strategy to support rules which begin with a
# direct or indirect reference to themselves.
#
# You don't normally use this directly, instead you should generate it by
# using the structuring method Parslet.rule.
#
class Parslet::Atoms::Entity < Parslet::Atoms::Base
  attr_reader :name, :block, :left_recursive, :owner
  def initialize(*args, &block)
    if args.first.is_a?(Symbol) || args.first.is_a?(String)
      name, label = args
      owner = nil
      left_recursive = false
    else
      owner, name, label, left_recursive = args
    end

    super()
    
    @owner = owner
    @name = name
    @label = label
    @left_recursive = left_recursive
    @block = block
    @parslet = nil
  end

  def try(source, context, consume_all)
    context.try_entity(self, source, consume_all)
  end

  def cache_key
    @owner ? [@owner.object_id, name] : object_id
  end
  
  def parslet
    return @parslet unless @parslet.nil?
    @parslet = @block.call
    raise_not_implemented if @parslet.nil?
    @parslet.label = @label
    @parslet
  end

  def to_s_inner(prec)
    name.to_s.upcase
  end  
private 
  def raise_not_implemented
    trace = caller.reject {|l| l =~ %r{#{Regexp.escape(__FILE__)}}} # blatantly stolen from dependencies.rb in activesupport
    exception = NotImplementedError.new("rule(#{name.inspect}) { ... }  returns nil. Still not implemented, but already used?")
    exception.set_backtrace(trace)
    
    raise exception
  end
end
