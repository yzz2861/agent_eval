# frozen_string_literal: true

require_relative "helper"

require "rexml/stream_writer"

module REXMLTests
  class StreamWriterTest < Test::Unit::TestCase
    class FailingOutput
      attr_reader :written

      def initialize(fail_times = 1, ignore = nil, fail_content = nil)
        @fail_times = fail_times
        @ignore = ignore
        @fail_content = fail_content
        @written = +""
      end

      def <<(content)
        if @fail_content && content == @fail_content
          @fail_content = nil
          raise IOError, "write failed"
        elsif @ignore && content.include?(@ignore)
          @written << content
        elsif @fail_times.positive?
          @fail_times -= 1
          raise IOError, "write failed"
        end

        @written << content unless @ignore
        self
      end

      def close
        raise "must not close borrowed output"
      end
    end

    def text_values(node)
      node.children.flat_map do |child|
        case child
        when REXML::Text
          [child.value]
        when REXML::Element
          text_values(child)
        else
          []
        end
      end
    end

    def equivalent_dom(&block)
      stream_output = +""
      stream_writer = REXML::StreamWriter.new(stream_output)
      block.call(stream_writer)
      stream_writer.finish

      document = REXML::Document.new
      block.call(DomBuilder.new(document))

      stream_document = REXML::Document.new(stream_output)
      [document, stream_document, normalize_tree(document),
       normalize_tree(stream_document)]
    end

    def normalize_tree(node)
      case node
      when REXML::Document
        node.children.map { |child| normalize_tree(child) }
      when REXML::Element
        {
          name: node.expanded_name,
          namespace: node.namespace,
          attributes: node.attributes.each_attribute
                              .reject(&:namespace_declaration?)
                              .sort_by(&:expanded_name)
                              .map do |attribute|
                                [attribute.prefix,
                                 attribute.namespace,
                                 attribute.name,
                                 attribute.value]
                              end,
          children: node.children.map { |child| normalize_tree(child) },
        }
      when REXML::Text
        [:text, node.value]
      when REXML::Comment
        [:comment, node.string]
      end
    end

    class DomBuilder
      def initialize(document)
        @document = document
        @elements = []
      end

      def start_element(name)
        element = REXML::Element.new(name)
        if @elements.empty?
          @document << element
        else
          @elements.last << element
        end
        @elements << element
        self
      end

      def attribute(name, value)
        @elements.last.add_attribute(name, value)
        self
      end

      def text(value)
        @elements.last.add_text(value)
        self
      end

      def comment(value)
        comment = REXML::Comment.new(value)
        if @elements.empty?
          @document << comment
        else
          @elements.last << comment
        end
        self
      end

      def end_element(name = nil)
        element = @elements.last
        unless name.nil? || element.expanded_name == name
          raise ArgumentError, "unexpected closing tag"
        end
        @elements.pop
        self
      end

      def finish
        self
      end
    end

    def test_elements_text_and_comments_match_dom
      document, stream_document, expected, actual = equivalent_dom do |writer|
        writer.start_element("root")
        writer.attribute("id", "one & <two>")
        writer.text("Hello, ")
        writer.start_element("child")
        writer.text("world")
        writer.comment("a note")
        writer.end_element
        writer.end_element
      end

      assert_equal(expected, actual)
      assert_equal("one & <two>",
                   stream_document.root.attributes.get_attribute("id").value)
      assert_equal(["Hello, ", "world"], text_values(document.root))
    end

    def test_namespace_scope_is_restored_after_element_closes
      output = +""
      writer = REXML::StreamWriter.new(output)
      writer.start_element("root")
      writer.attribute("xmlns:a", "https://example.com/a")
      writer.start_element("a:first")
      writer.attribute("a:name", "one")
      writer.end_element
      writer.start_element("child")
      writer.attribute("xmlns:a", "https://example.com/local")
      writer.attribute("xmlns:b", "https://example.com/b")
      writer.start_element("b:second")
      writer.end_element
      writer.start_element("a:third")
      writer.end_element
      writer.end_element
      writer.start_element("other")
      writer.attribute("xmlns:a", "https://example.com/a")
      writer.start_element("a:fourth")
      writer.end_element
      writer.end_element
      writer.end_element
      writer.finish

      document = REXML::Document.new(output)
      assert_equal("https://example.com/a",
                   document.root.elements["a:first"].namespace)
      assert_equal("https://example.com/local",
                   document.root.elements["child/a:third"].namespace)
      assert_equal("https://example.com/b",
                   document.root.elements["child/b:second"].namespace)
      assert_equal("https://example.com/a",
                   document.root.elements["other/a:fourth"].namespace)
    end

    def test_default_namespace_does_not_apply_to_attributes
      _document, _stream_document, expected, actual = equivalent_dom do |writer|
        writer.start_element("root")
        writer.attribute("xmlns", "https://example.com/default")
        writer.attribute("plain", "value")
        writer.end_element
      end

      assert_equal(expected, actual)
    end

    def test_attribute_after_child_is_rejected
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      writer.start_element("child")
      writer.end_element

      error = assert_raise(RuntimeError) do
        writer.attribute("name", "value")
      end
      assert_equal("can't add attribute after child content has started",
                   error.message)
    end

    def test_duplicate_attributes_use_expanded_name
      output = +""
      writer = REXML::StreamWriter.new(output)
      writer.start_element("root")
      writer.attribute("xmlns:a", "https://example.com/ns")
      writer.attribute("xmlns:b", "https://example.com/ns")
      writer.attribute("a:name", "one")

      error = assert_raise(ArgumentError) do
        writer.attribute("b:name", "two")
      end
      assert_match(/duplicate attribute/, error.message)
    end

    def test_same_qualified_attribute_is_duplicate_even_before_flush
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      writer.attribute("name", "one")

      error = assert_raise(ArgumentError) do
        writer.attribute("name", "two")
      end
      assert_equal("duplicate attribute \"name\"", error.message)
    end

    def test_duplicate_namespace_declaration
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      writer.attribute("xmlns:a", "https://example.com/a")

      error = assert_raise(ArgumentError) do
        writer.attribute("xmlns:a", "https://example.com/a")
      end
      assert_equal("duplicate attribute \"xmlns:a\"", error.message)
    end

    def test_undefined_element_namespace
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      writer.start_element("a:child")

      assert_raise(REXML::ParseException) do
        writer.text("content")
      end
      assert_equal(%w[root a:child],
                   writer.instance_variable_get(:@elements)
                              .map { |element| element[:name] })
    end

    def test_undefined_attribute_namespace
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      writer.attribute("a:name", "value")

      assert_raise(REXML::ParseException) do
        writer.text("content")
      end
    end

    def test_write_failure_keeps_unfinished_start_tag
      output = FailingOutput.new
      writer = REXML::StreamWriter.new(output)
      writer.start_element("root")
      writer.attribute("name", "value")

      assert_raise(IOError) do
        writer.start_element("child")
      end
      assert_equal("", output.written)
      assert_equal(%w[root], writer.instance_variable_get(:@elements)
                                  .map { |element| element[:name] })

      writer.attribute("other", "value")
      writer.start_element("child")
      writer.end_element
      writer.end_element
      writer.finish
      document = REXML::Document.new(output.written)
      assert_equal(["name", "other"], document.root.attributes.keys.sort)
      assert_equal("root", document.root.expanded_name)
    end

    def test_write_failure_keeps_open_end_tag_state
      output = FailingOutput.new(0, nil, "</root>")
      writer = REXML::StreamWriter.new(output)
      writer.start_element("root")
      writer.text("content")

      assert_raise(IOError) { writer.end_element }
      assert_equal("<root>content", output.written)
      assert_equal(%w[root], writer.instance_variable_get(:@elements)
                                  .map { |element| element[:name] })

      writer.end_element
      writer.finish
      assert_equal("<root>content</root>", output.written)
    end

    def test_borrowed_io_is_not_closed
      output = FailingOutput.new(0)
      writer = REXML::StreamWriter.new(output)
      writer.start_element("root").end_element.finish

      assert_equal("<root/>", output.written)
    end

    def test_finish_checks_tag_balance
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      writer.start_element("child")

      error = assert_raise(REXML::StreamWriter::UnbalancedTagsError) do
        writer.finish
      end
      assert_equal("unclosed element(s): root, child", error.message)
    end

    def test_wrong_end_tag_is_rejected
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      error = assert_raise(ArgumentError) do
        writer.end_element("other")
      end
      assert_equal('expected closing tag for "root", got "other"',
                   error.message)
    end

    def test_comment_and_text_are_escaped_and_reparse
      output = +""
      writer = REXML::StreamWriter.new(output)
      writer.start_element("root")
      writer.attribute("quote", %q{' and "})
      writer.text(%q{<a href="?a=1&b=2">})
      writer.comment("no double hyphen")
      writer.end_element
      writer.finish

      document = REXML::Document.new(output)
      assert_equal(%q{<a href="?a=1&b=2">}, document.root.text)
      assert_equal(%q{' and "},
                   document.root.attributes.get_attribute("quote").value)
      assert_equal("no double hyphen", document.root.comments.first.string)
    end

    def test_invalid_comment
      writer = REXML::StreamWriter.new(+"")
      writer.start_element("root")
      assert_raise(ArgumentError) { writer.comment("bad -- comment") }
      assert_raise(ArgumentError) { writer.comment("ends with -") }
    end
  end
end
