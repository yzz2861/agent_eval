# frozen_string_literal: false

require "stringio"

require_relative "helper"

module REXMLTests
  class StreamWriterTest < Test::Unit::TestCase
    class FlakyIO
      def initialize
        @buffer = +""
        @failures = 0
      end

      def fail_next(count = 1)
        @failures = count
      end

      def <<(chunk)
        if @failures > 0
          @failures -= 1
          raise IOError, "simulated write failure"
        end
        @buffer << chunk
        self
      end

      def to_s
        @buffer
      end
    end

    def write_document
      io = StringIO.new
      writer = REXML::StreamWriter.new(io)
      yield writer
      writer.finish
      io.string
    end

    def canonical(node)
      case node
      when REXML::Document
        node.children.filter_map {|child| canonical(child) }
      when REXML::Element
        attributes = node.attributes.each_attribute.map do |attribute|
          [attribute.namespace, attribute.name, attribute.value]
        end
        [:element, node.namespace, node.name, attributes.sort,
         node.children.filter_map {|child| canonical(child) }]
      when REXML::Text
        [:text, node.value]
      when REXML::Comment
        [:comment, node.string]
      end
    end

    def assert_same_document(expected, xml)
      assert_equal(canonical(REXML::Document.new(expected)),
                   canonical(REXML::Document.new(xml)))
    end

    def test_basic_document_matches_dom
      document = REXML::Document.new
      root = document.add_element("root", "a" => "1", "b" => "two")
      child = root.add_element("child")
      child.add_text("hello <world> & friends")
      root.add_element("empty")
      root.add(REXML::Comment.new("a comment"))

      xml = write_document do |writer|
        writer.start_element("root", "a" => "1", "b" => "two")
        writer.start_element("child")
        writer.text("hello <world> & friends")
        writer.end_element
        writer.start_element("empty")
        writer.end_element
        writer.comment("a comment")
        writer.end_element
      end

      assert_same_document(document.to_s, xml)
    end

    def test_namespaced_document_matches_dom
      document = REXML::Document.new
      root = document.add_element("p:root", "xmlns:p" => "urn:one",
                                  "xmlns:q" => "urn:two")
      root.add_element("q:item", "p:id" => "7")

      xml = write_document do |writer|
        writer.start_element("p:root",
                             "xmlns:p" => "urn:one", "xmlns:q" => "urn:two")
        writer.start_element("q:item", "p:id" => "7")
        writer.end_element
        writer.end_element
      end

      assert_same_document(document.to_s, xml)
    end

    def test_empty_element_is_self_closed
      xml = write_document do |writer|
        writer.start_element("root")
        writer.end_element
      end
      assert_equal("<root/>", xml)
    end

    def test_text_escaping
      xml = write_document do |writer|
        writer.start_element("root", "attr" => %q{a<b&"c"})
        writer.text("1 < 2 & 3 > 2 ]]>")
        writer.end_element
      end
      expected = %q{<root attr="a&lt;b&amp;&quot;c&quot;">} +
                 "1 &lt; 2 &amp; 3 &gt; 2 ]]&gt;</root>"
      assert_equal(expected, xml)
    end

    def test_attribute_after_text_is_rejected
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      writer.text("content")
      assert_raise(REXML::StreamWriter::Error) do
        writer.attribute("a", "1")
      end
    end

    def test_attribute_after_child_element_is_rejected
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      writer.start_element("child")
      writer.end_element
      assert_raise(REXML::StreamWriter::Error) do
        writer.attribute("a", "1")
      end
    end

    def test_attribute_without_open_element_is_rejected
      writer = REXML::StreamWriter.new(StringIO.new)
      assert_raise(REXML::StreamWriter::Error) do
        writer.attribute("a", "1")
      end
    end

    def test_duplicate_attribute_same_name
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root", "a" => "1")
      assert_raise(REXML::StreamWriter::Error) do
        writer.attribute("a", "2")
      end
    end

    def test_duplicate_attribute_by_expanded_name
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root",
                           "xmlns:p" => "urn:x", "xmlns:q" => "urn:x")
      writer.attribute("p:item", "1")
      assert_raise(REXML::StreamWriter::Error) do
        writer.attribute("q:item", "2")
      end
    end

    def test_same_local_name_in_different_namespaces_is_allowed
      xml = write_document do |writer|
        writer.start_element("root",
                             "xmlns:p" => "urn:one", "xmlns:q" => "urn:two",
                             "p:item" => "1", "q:item" => "2")
        writer.end_element
      end
      attributes = REXML::Document.new(xml).root.attributes
      assert_equal("1", attributes["p:item"])
      assert_equal("2", attributes["q:item"])
    end

    def test_default_namespace_does_not_apply_to_attributes
      xml = write_document do |writer|
        writer.start_element("root",
                             "xmlns" => "urn:default",
                             "xmlns:p" => "urn:default",
                             "item" => "1", "p:item" => "2")
        writer.end_element
      end
      attributes = REXML::Document.new(xml).root.attributes
      assert_equal("1", attributes["item"])
      assert_equal("2", attributes["p:item"])
    end

    def test_namespace_scope_ends_with_element
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root", "xmlns:p" => "urn:x")
      writer.start_element("p:child")
      writer.end_element
      writer.end_element
      assert_raise(REXML::UndefinedNamespaceException) do
        writer.start_element("p:orphan")
      end
    end

    def test_namespace_shadowing
      xml = write_document do |writer|
        writer.start_element("root", "xmlns:p" => "urn:outer")
        writer.start_element("child", "xmlns:p" => "urn:inner")
        writer.attribute("p:mark", "yes")
        writer.end_element
        writer.end_element
      end
      document = REXML::Document.new(xml)
      child = document.root.elements["child"]
      assert_equal("urn:inner",
                   child.attributes.get_attribute("p:mark").namespace)
    end

    def test_undeclared_prefix_on_element
      writer = REXML::StreamWriter.new(StringIO.new)
      assert_raise(REXML::UndefinedNamespaceException) do
        writer.start_element("p:root")
      end
    end

    def test_undeclared_prefix_on_attribute
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      assert_raise(REXML::UndefinedNamespaceException) do
        writer.attribute("p:a", "1")
      end
    end

    def test_xml_prefix_is_predefined
      xml = write_document do |writer|
        writer.start_element("root", "xml:lang" => "en")
        writer.end_element
      end
      assert_equal("en", REXML::Document.new(xml).root.attributes["xml:lang"])
    end

    def test_comment_content_validation
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      assert_raise(REXML::StreamWriter::Error) do
        writer.comment("bad -- comment")
      end
      assert_raise(REXML::StreamWriter::Error) do
        writer.comment("trailing-")
      end
    end

    def test_end_element_name_mismatch
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      assert_raise(REXML::StreamWriter::Error) do
        writer.end_element("other")
      end
    end

    def test_end_element_without_open_element
      writer = REXML::StreamWriter.new(StringIO.new)
      assert_raise(REXML::StreamWriter::Error) do
        writer.end_element
      end
    end

    def test_invalid_names_are_rejected
      writer = REXML::StreamWriter.new(StringIO.new)
      assert_raise(REXML::StreamWriter::Error) do
        writer.start_element("not a name")
      end
      writer.start_element("root")
      assert_raise(REXML::StreamWriter::Error) do
        writer.attribute("1bad", "x")
      end
    end

    def test_finish_requires_balanced_tags
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      writer.start_element("child")
      error = assert_raise(REXML::StreamWriter::Error) do
        writer.finish
      end
      assert_include(error.message, "child")
    end

    def test_finish_does_not_close_output
      io = StringIO.new
      writer = REXML::StreamWriter.new(io)
      writer.start_element("root")
      writer.end_element
      assert_same(io, writer.finish)
      assert_false(io.closed?)
    end

    def test_writes_after_finish_are_rejected
      writer = REXML::StreamWriter.new(StringIO.new)
      writer.start_element("root")
      writer.end_element
      writer.finish
      assert_true(writer.finished?)
      assert_raise(REXML::StreamWriter::Error) do
        writer.start_element("again")
      end
      assert_raise(REXML::StreamWriter::Error) do
        writer.text("again")
      end
    end

    def test_failed_end_element_keeps_state
      io = FlakyIO.new
      writer = REXML::StreamWriter.new(io)
      writer.start_element("root")
      io.fail_next
      assert_raise(IOError) do
        writer.end_element
      end
      assert_raise(REXML::StreamWriter::Error) do
        writer.finish
      end
      writer.end_element
      writer.finish
      assert_equal("<root/>", io.to_s)
    end

    def test_failed_start_element_keeps_state
      io = FlakyIO.new
      writer = REXML::StreamWriter.new(io)
      writer.start_element("root")
      io.fail_next
      assert_raise(IOError) do
        writer.start_element("child")
      end
      writer.start_element("child")
      writer.end_element
      writer.end_element
      writer.finish
      assert_equal("<root><child/></root>", io.to_s)
    end

    def test_failed_attribute_keeps_state
      io = FlakyIO.new
      writer = REXML::StreamWriter.new(io)
      writer.start_element("root")
      io.fail_next
      assert_raise(IOError) do
        writer.attribute("a", "1")
      end
      writer.attribute("a", "1")
      writer.end_element
      writer.finish
      assert_equal(%q{<root a="1"/>}, io.to_s)
    end

    def test_failed_text_keeps_state
      io = FlakyIO.new
      writer = REXML::StreamWriter.new(io)
      writer.start_element("root")
      io.fail_next
      assert_raise(IOError) do
        writer.text("hi")
      end
      writer.text("hi")
      writer.end_element
      writer.finish
      assert_equal("<root>hi</root>", io.to_s)
    end
  end
end
