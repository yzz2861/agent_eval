# frozen_string_literal: true

require "test/unit"
require "rexml/document"
require "rexml/xpath"
require "rexml/parseexception"

module REXMLTests
  class TestXPathCompiled < Test::Unit::TestCase
    include REXML

    module SyntaxParseCounter
      @count = 0

      class << self
        attr_accessor :count
      end

      def parse(path)
        SyntaxParseCounter.count += 1
        super
      end
    end

    unless REXML::Parsers::XPathParser.ancestors.include?(SyntaxParseCounter)
      REXML::Parsers::XPathParser.prepend(SyntaxParseCounter)
    end

    def setup
      @document = Document.new(<<-XML)
        <root>
          <a id="1">one</a>
          <a id="2">two</a>
          <a id="3">three</a>
        </root>
      XML
    end

    def test_match_has_same_semantics_as_xpath_match
      expressions = [
        "//a",
        "//a[@id=$id]",
        "//a[position()=$position]",
        "count(//a)",
        "//a[1] | //a[3]",
        "string(//a[@id=$id])",
      ]
      variables = {"id" => "2", "position" => 2}

      expressions.each do |expression|
        plan = XPath.compile(expression)
        assert_equal(XPath.match(@document, expression, nil, variables),
                     plan.match(@document, nil, variables),
                     expression)
      end
    end

    def test_first_and_each_use_the_compiled_plan
      plan = XPath.compile("//a[@id=$id]")
      variables = {"id" => "2"}

      assert_equal("two", plan.first(@document, nil, variables).text)

      values = []
      plan.each(@document, nil, variables) do |node|
        values << node.text
      end
      assert_equal(["two"], values)
    end

    def test_xpath_wrappers_accept_a_compiled_plan
      plan = XPath.compile("//a[@id=$id]")
      variables = {"id" => "2"}

      assert_equal(["two"],
                   XPath.match(@document, plan, nil, variables).collect(&:text))
      assert_equal("two", XPath.first(@document, plan, nil, variables).text)

      values = []
      XPath.each(@document, plan, nil, variables) do |node|
        values << node.text
      end
      assert_equal(["two"], values)
    end

    def test_accepts_namespace_mapping_at_evaluation_time
      document = Document.new(<<-XML)
        <root xmlns="https://example.test/ns">
          <item id="one"/>
        </root>
      XML
      plan = XPath.compile("/ns:root/ns:item/@id")

      assert_equal("one",
                   plan.first(document,
                              {"ns" => "https://example.test/ns"}).value)
      assert_nil(plan.first(document,
                           {"ns" => "https://example.test/other"}))
    end

    def test_syntax_errors_are_reported_at_compile_time
      assert_raise(ParseException) do
        XPath.compile("//[")
      end
    end

    def test_missing_variables_are_reported_at_evaluation_time
      plan = assert_nothing_raised(ParseException) do
        XPath.compile("//a[@id=$id]")
      end

      exception = assert_raise(XPath::UndefinedVariable) do
        plan.match(@document)
      end
      assert_equal("id", exception.name)
    end

    def test_unreachable_missing_variables_are_not_evaluated
      assert_equal([true],
                   XPath.compile("true() or $missing = 'x'").match(@document))
      assert_equal([false],
                   XPath.compile("false() and $missing = 'x'").match(@document))
    end

    def test_repeated_evaluation_does_not_reparse_expression
      SyntaxParseCounter.count = 0
      plan = XPath.compile("//a[@id=$id and position()=$position]")
      assert_equal(1, SyntaxParseCounter.count)

      3.times do |index|
        variables = {"id" => (index + 1).to_s, "position" => index + 1}
        assert_equal(["one", "two", "three"][index, 1],
                     plan.match(@document, nil, variables).collect(&:text))
      end

      assert_equal(1, SyntaxParseCounter.count)
    end

    def test_plan_is_frozen_and_has_no_evaluation_state
      plan = XPath.compile("//a[position()=last()]")
      plan.match(@document)

      assert(plan.frozen?)
      assert(plan.instance_variable_get(:@path_stack).frozen?)
      assert_equal([:@options, :@path_stack], plan.instance_variables.sort)
    end

    def test_shared_plan_is_isolated_between_threads
      plan = XPath.compile("//ns:item[@id=$id][position()=last()]/text()")
      threads = 8.times.collect do |index|
        namespace = "https://example.test/#{index}"
        document = Document.new(<<-XML)
          <root xmlns="#{namespace}">
            <item id="target">wrong</item>
            <item id="other">wrong</item>
            <item id="target">right-#{index}</item>
          </root>
        XML

        Thread.new do
          namespaces = {"ns" => namespace}
          variables = {"id" => "target"}
          100.times do
            result = plan.match(document, namespaces, variables)
            values = result.collect(&:to_s)
            unless values == ["right-#{index}"]
              raise "unexpected result: #{result.inspect}"
            end
          end
        end
      end

      threads.each(&:join)
    end

    def test_failed_evaluation_does_not_corrupt_plan
      plan = XPath.compile("//a[@id=$id]")

      assert_raise(TypeError) do
        plan.match(@document, nil, {"id" => Object.new})
      end
      assert_raise(XPath::UndefinedVariable) do
        plan.match(@document)
      end
      assert_equal(["two"],
                   plan.match(@document, nil, {"id" => "2"}).collect(&:text))
    end
  end
end
