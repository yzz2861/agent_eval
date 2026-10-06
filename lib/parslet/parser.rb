
# The base class for all your parsers. Use as follows: 
#
#   require 'parslet'
#        
#   class MyParser < Parslet::Parser
#     rule(:a) { str('a').repeat }
#     root(:a)        
#   end
#        
#   pp MyParser.new.parse('aaaa')   # => 'aaaa'
#   pp MyParser.new.parse('bbbb')   # => Parslet::Atoms::ParseFailed: 
#                                   #    Don't know what to do with bbbb at line 1 char 1.
#
# Parslet::Parser is also a grammar atom. This means that you can mix full 
# fledged parsers freely with small parts of a different parser. 
#
# Example: 
#   class ParserA < Parslet::Parser
#     root :aaa
#     rule(:aaa) { str('a').repeat(3,3) }
#   end
#   class ParserB < Parslet::Parser
#     root :expression
#     rule(:expression) { str('b') >> ParserA.new >> str('b') }
#   end
#
# In the above example, ParserB would parse something like 'baaab'. 
#
class Parslet::Parser < Parslet::Atoms::Base
  include Parslet

  class << self # class methods
    # Names of all rules declared with Parslet::ClassMethods#rule on this
    # class, including rules inherited from parser superclasses.
    #
    # @return [Array<Symbol>]
    def parslet_rule_names
      ancestors.reverse.inject([]) do |names, mod|
        if mod.instance_variable_defined?(:@parslet_rules)
          names.concat(mod.instance_variable_get(:@parslet_rules))
        end
        names
      end.uniq
    end

    # Statically checks the grammar without parsing any business input. See
    # Parslet::GrammarCheck for the kinds of non-progressing constructs that
    # are reported.
    #
    #   class MyParser < Parslet::Parser
    #     rule(:a) { str('').repeat }
    #     root(:a)
    #   end
    #   result = MyParser.grammar_check
    #   result.ok?              # => false
    #   puts result.report
    #
    # @return [Parslet::GrammarCheck::Result]
    def grammar_check
      Parslet::GrammarCheck.analyze(self, parslet_rule_names)
    end

    # Like {.grammar_check}, but raises {Parslet::GrammarError} at startup
    # when a non-progressing construct is found. Call this once, before
    # parsing business input:
    #
    #   MyParser.grammar_check!
    #
    def grammar_check!
      grammar_check.verify!
    end

    # Define the parsers #root function. This is the place where you start 
    # parsing; if you have a rule for 'file' that describes what should be 
    # in a file, this would be your root declaration: 
    #
    #   class Parser
    #     root :file
    #     rule(:file) { ... }
    #   end
    #
    # #root declares a 'parse' function that works just like the parse 
    # function that you can call on a simple parslet, taking a string as input
    # and producing parse output. 
    #
    # In a way, #root is a shorthand for: 
    #
    #   def parse(str)
    #     your_parser_root.parse(str)
    #   end
    #
    def root(name)
      undef_method :root if method_defined? :root
      define_method(:root) do
        self.send(name)
      end
    end
  end
  
  def try(source, context, consume_all)
    root.try(source, context, consume_all)
  end
  
  def to_s_inner(prec)
    root.to_s(prec)
  end

  # Instance level entry point for {Parslet::GrammarCheck}. This reads no
  # input; it only expands and analyses the parser's atom graph.
  #
  def grammar_check
    names = self.class.respond_to?(:parslet_rule_names) ?
      self.class.parslet_rule_names :
      []
    Parslet::GrammarCheck.analyze(self, names)
  end

  # Instance level counterpart of {Parslet::Parser.grammar_check!}.
  #
  def grammar_check!
    grammar_check.verify!
  end
end
