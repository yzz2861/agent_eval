# frozen_string_literal: false

module REXMLTests
  class TestXPathPlan < Test::Unit::TestCase
    include REXML

    def test_reuses_compiled_expression
      documents = [
        Document.new("<root><item id='1'/><item id='2'/></root>"),
        Document.new("<root><item id='2'/><item id='3'/></root>"),
      ]
      plan = nil
      parse_count = [0]
      trace = TracePoint.new(:call) do |event|
        if event.method_id == :parse &&
             event.self.is_a?(Parsers::XPathParser)
          parse_count[0] += 1
        end
      end
      trace.enable do
        plan = XPath.compile("/root/item[@id=$id]")
        assert_equal(1, parse_count[0])
        assert_equal(["2"],
                     ids(plan.match(documents[0], nil, {"id" => "2"})))
        assert_equal(1, parse_count[0])
        assert_equal(["2", "3"],
                     ids(plan.match(documents[1], nil, {"id" => "2"})) +
                     ids(plan.match(documents[1], nil, {"id" => "3"})))
        assert_equal(1, parse_count[0])
      end
    end

    def test_results_match_xpath_match
      xml = "<root xmlns='http://example.com/default'><child id='1'/><child id='2'/></root>"
      document = Document.new(xml)
      namespaces = {"e" => "http://example.com/default"}
      plan = XPath.compile("/e:root/e:child[@id=$id]")

      assert_equal(XPath.match(document,
                               "/e:root/e:child[@id=$id]",
                               namespaces,
                               {"id" => "2"}),
                   plan.match(document, namespaces, {"id" => "2"}))
      assert_equal(XPath.first(document,
                               "/e:root/e:child[@id=$id]",
                               namespaces,
                               {"id" => "1"}),
                   plan.first(document, namespaces, {"id" => "1"}))

      each_ids = []
      plan.each(document, namespaces, {"id" => "2"}) do |child|
        each_ids << child.attributes["id"]
      end
      assert_equal(["2"], each_ids)
    end

    def test_call_is_alias_for_match
      document = Document.new("<root><item id='1'/></root>")
      plan = XPath.compile("/root/item[@id=$id]")

      assert_equal(plan.match(document, nil, {"id" => "1"}),
                   plan.call(document, nil, {"id" => "1"}))
    end

    def test_default_expression
      document = Document.new("<root><item/></root>")
      plan = XPath.compile

      assert_equal(XPath.match(document.root),
                   plan.match(document.root))
    end

    def test_non_nodeset_results_match_xpath_match
      document = Document.new("<root><item/><item/></root>")
      plan = XPath.compile("count(/root/item)")

      assert_equal(XPath.match(document, "count(/root/item)"),
                   plan.match(document))
      assert_equal(XPath.first(document, "count(/root/item)"),
                   plan.first(document))
    end

    def test_compile_options_are_used_for_each_evaluation
      document = Document.new("<root xmlns='http://example.com/ns'><item/></root>")
      plan = XPath.compile("/root/item", strict: true)

      assert_equal([], plan.match(document))
      assert_equal(XPath.match(document, "/root/item", nil, {}, strict: true),
                   plan.match(document))
    end

    def test_evaluation_does_not_store_context
      document = Document.new("<root><item id='1'/></root>")
      plan = XPath.compile("/root/item[position() = last() and name() = $name]")
      plan.freeze

      assert_equal(document.root.elements.to_a("item"),
                   plan.match(document, nil, {"name" => "item"}))

      assert_equal([:@path_stack, :@options], plan.instance_variables)
    end

    def test_syntax_error_is_reported_at_compile_time
      assert_raise(ParseException) do
        XPath.compile("@@")
      end
    end

    def test_variable_issues_are_reported_at_evaluation_time
      plan = nil
      assert_nothing_raised do
        plan = XPath.compile("/root/item[@id=$id]")
      end
      document = Document.new("<root><item id='1'/></root>")

      assert_raise(TypeError) do
        plan.match(document, nil, {"id" => Object.new})
      end
      assert_equal([], plan.match(document, nil, {"id" => "2"}))
    end

    def test_evaluation_does_not_mutate_compiled_expression
      document = Document.new("<root><item id='1'/><item id='2'/><item id='3'/></root>")
      plan = XPath.compile("/root/item[position() = last() - 1][@id=$id]")

      2.times do
        assert_equal(["2"],
                     ids(plan.match(document, nil, {"id" => "2"})))
      end
    end

    def test_concurrent_evaluations_are_isolated
      documents = 4.times.collect do |index|
        Document.new("<root><item id='" + index.to_s + "'/><item id='shared'/></root>")
      end
      plan = XPath.compile("/root/item[position() = last() or @id=$id]")
      queue = Queue.new

      threads = documents.each_with_index.collect do |document, index|
        Thread.new do
          100.times do
            matched_ids = ids(plan.match(document, nil, {"id" => index.to_s})).sort
            queue << [index, matched_ids]
          end
        end
      end
      threads.each(&:join)

      results = Array.new(4) { [] }
      until queue.empty?
        index, ids = queue.pop
        results[index] << ids
      end
      documents.each_with_index do |_, index|
        assert_equal(Array.new(100, [index.to_s, "shared"]),
                     results[index])
      end
    end

    private

    def ids(nodes)
      nodes.collect {|node| node.attributes["id"]}
    end
  end
end
