# -*- coding: utf-8 -*-
# frozen_string_literal: false

require "test-unit"

require "rexml/document"
require "rexml/xinclude"

module REXMLTests
  class TestXInclude < Test::Unit::TestCase
    XI = "http://www.w3.org/2001/XInclude"

    def setup
      @resources = {}
      @resolver = lambda do |uri|
        @resources[uri]
      end
    end

    def expand(xml, base: "file:///doc/main.xml", &resolver)
      document = REXML::Document.new(xml)
      REXML::XInclude.expand(document, resolver || @resolver, base: base)
      document
    end

    def include_xml(href, attributes = "", inner = "")
      %Q{<xi:include xmlns:xi="#{XI}" href="#{href}"#{attributes}>#{inner}</xi:include>}
    end

    def wrap(inner)
      %Q{<root xmlns:xi="#{XI}">#{inner}</root>}
    end

    def put(uri, content)
      @resources[uri] = content
    end

    # -- parse="xml" -----------------------------------------------------

    def test_xml_include_inserts_root_element
      put("file:///doc/parts/chunk.xml", "<chunk>hello</chunk>")
      document = expand(wrap(include_xml("parts/chunk.xml")))
      assert_equal("chunk", document.root.children.first.name)
      assert_equal("hello", document.root.elements["chunk"].text)
    end

    def test_xml_include_relative_uri_is_resolved_against_base
      put("file:///doc/sub/leaf.xml", "<leaf>deep</leaf>")
      document = expand(wrap(include_xml("sub/leaf.xml")))
      chunk = document.root.children.first
      assert_equal("leaf", chunk.name)
      assert_equal("sub/leaf.xml", chunk.attribute("xml:base").value)
    end

    def test_xml_include_resolves_relative_to_included_file
      put("file:///doc/sub/mid.xml",
          %Q{<mid xmlns:xi="#{XI}"><xi:include href="leaf.xml"/></mid>})
      put("file:///doc/sub/leaf.xml", "<leaf>deep</leaf>")
      document = expand(wrap(include_xml("sub/mid.xml")))
      leaf = REXML::XPath.first(document, "//leaf")
      assert_not_nil(leaf)
      assert_equal("deep", leaf.text)
      assert_equal("leaf.xml", leaf.attribute("xml:base").value)
    end

    def test_xml_include_resource_with_same_location_base_omits_xml_base
      put("file:///doc/parts/chunk.xml", "<chunk>x</chunk>")
      xml = %Q{<root xmlns:xi="#{XI}" xml:base="file:///doc/parts/chunk.xml">} +
            include_xml("chunk.xml") + "</root>"
      document = expand(xml, base: "file:///elsewhere/main.xml")
      included = document.root.children.first
      assert_equal("chunk", included.name)
      assert_nil(included.attribute("xml:base"))
    end

    def test_xml_include_relative_reference_uses_relative_path
      put("file:///doc/parts/chunk.xml", "<chunk>x</chunk>")
      xml = %Q{<root xmlns:xi="#{XI}" xml:base="file:///doc/parts/here.xml">} +
            include_xml("chunk.xml") + "</root>"
      document = expand(xml, base: "file:///elsewhere/main.xml")
      included = document.root.children.first
      assert_equal("chunk.xml", included.attribute("xml:base").value)
    end

    def test_xml_include_preserves_default_namespace_of_host
      put("file:///doc/chunk.xml", "<chunk/>")
      document = REXML::Document.new(
        %Q{<root xmlns="urn:host" xmlns:xi="#{XI}">#{include_xml("chunk.xml")}</root>})
      REXML::XInclude.expand(document, @resolver, base: "file:///doc/main.xml")
      chunk = document.root.children.first
      assert_equal("", chunk.attribute("xmlns").value)
      assert_equal("", chunk.namespace)
      assert_equal("urn:host", document.root.namespace)
    end

    def test_xml_include_keeps_included_default_namespace
      put("file:///doc/chunk.xml",
          %Q{<chunk xmlns="urn:included"><child/></chunk>})
      document = REXML::Document.new(
        %Q{<root xmlns="urn:host" xmlns:xi="#{XI}">#{include_xml("chunk.xml")}</root>})
      REXML::XInclude.expand(document, @resolver, base: "file:///doc/main.xml")
      chunk = document.root.children.first
      assert_equal("urn:included", chunk.namespace)
      child = chunk.children.first
      assert_equal("urn:included", child.namespace)
    end

    def test_xml_include_preserves_prefixed_namespace
      put("file:///doc/chunk.xml",
          %Q{<chunk xmlns:a="urn:a"><a:item/></chunk>})
      document = expand(wrap(include_xml("chunk.xml")))
      item = REXML::XPath.first(document, "//a:item")
      assert_equal("urn:a", item.namespace)
      chunk = document.root.children.first
      assert_equal("urn:a", chunk.attribute("xmlns:a").value)
    end

    def test_xml_include_top_level_comments_and_pis
      put("file:///doc/chunk.xml",
          %Q{<!-- c --><?pi data?><chunk>x</chunk>})
      document = expand(wrap(include_xml("chunk.xml")))
      classes = document.root.children.map(&:class)
      assert_include(classes, REXML::Comment)
      assert_include(classes, REXML::Instruction)
      assert_equal("x", REXML::XPath.first(document, "//chunk").text)
    end

    # -- parse="text" ----------------------------------------------------

    def test_text_include_inserts_text_node
      put("file:///doc/note.txt", "plain text")
      document = expand(wrap(include_xml("note.txt", ' parse="text"')))
      assert_equal("plain text", document.root.text)
      assert_not_nil(REXML::XPath.first(document, "//text()"))
    end

    def test_text_include_normalizes_line_endings
      put("file:///doc/note.txt", "a\r\nb\rc")
      document = expand(wrap(include_xml("note.txt", ' parse="text"')))
      assert_equal("a\nb\nc", document.root.text)
    end

    def test_text_include_does_not_emit_xml_base
      put("file:///doc/note.txt", "x")
      document = expand(wrap(include_xml("note.txt", ' parse="text"')))
      assert_nil(document.root.attribute("xml:base"))
    end

    # -- fallback --------------------------------------------------------

    def test_fallback_is_used_when_resource_missing
      document = expand(wrap(include_xml("missing.xml", "",
                                         %Q{<xi:fallback>fb</xi:fallback>})))
      assert_equal("fb", document.root.text)
    end

    def test_missing_include_without_fallback_is_removed
      document = expand(wrap(%Q{<a>1</a>#{include_xml("missing.xml")}<b>2</b>}))
      assert_equal(%w{a b}, document.root.children.map(&:name))
    end

    def test_resource_error_uses_fallback
      @resolver = lambda do |uri|
        raise REXML::XInclude::ResourceError, "boom: #{uri}"
      end
      document = expand(wrap(include_xml("missing.xml", "",
                                         %Q{<xi:fallback>fb</xi:fallback>})))
      assert_equal("fb", document.root.text)
    end

    def test_fallback_content_may_itself_include
      put("file:///doc/replacement.xml", "<replacement/>")
      document = expand(wrap(
        %Q{<xi:include href="missing.xml">} +
        %Q{<xi:fallback>#{include_xml("replacement.xml")}</xi:fallback>} +
        %Q{</xi:include>}))
      assert_equal("replacement", document.root.children.first.name)
    end

    # -- error handling --------------------------------------------------

    def test_malformed_xml_is_fatal_and_not_swallowed_by_fallback
      put("file:///doc/bad.xml", "<oops><unclosed>")
      assert_raise(REXML::XInclude::ParseError) do
        expand(wrap(include_xml("bad.xml", "",
                                %Q{<xi:fallback>fb</xi:fallback>})))
      end
    end

    def test_other_resolver_errors_propagate
      called = false
      @resolver = lambda do |uri|
        called = true
        raise RuntimeError, "database offline"
      end
      error = assert_raise(RuntimeError) do
        expand(wrap(include_xml("chunk.xml", "",
                                %Q{<xi:fallback>fb</xi:fallback>})))
      end
      assert_equal("database offline", error.message)
      assert(called)
    end

    def test_xpointer_is_rejected
      put("file:///doc/chunk.xml", "<chunk/>")
      assert_raise(REXML::XInclude::UnsupportedError) do
        expand(wrap(include_xml("chunk.xml",
                                ' xpointer="xpointer(/chunk)"')))
      end
    end

    def test_fragment_identifier_is_rejected
      put("file:///doc/chunk.xml", "<chunk/>")
      assert_raise(REXML::XInclude::UnsupportedError) do
        expand(wrap(include_xml("chunk.xml#frag")))
      end
    end

    def test_same_document_include_without_href_is_rejected
      assert_raise(REXML::XInclude::UnsupportedError) do
        expand(wrap(%Q{<xi:include xmlns:xi="#{XI}"/>}))
      end
    end

    def test_unknown_parse_value_is_rejected
      assert_raise(REXML::XInclude::UnsupportedError) do
        expand(wrap(include_xml("x", ' parse="bogus"')))
      end
    end

    def test_encoding_attribute_rejected_for_parse_xml
      put("file:///doc/chunk.xml", "<chunk/>")
      assert_raise(REXML::XInclude::FatalError) do
        expand(wrap(include_xml("chunk.xml", ' encoding="EUC-JP"')))
      end
    end

    def test_unexpected_element_child_is_fatal
      assert_raise(REXML::XInclude::FatalError) do
        expand(wrap(%Q{<xi:include xmlns:xi="#{XI}" href="x">} +
                    %Q{<xi:bogus/></xi:include>}))
      end
    end

    def test_relative_href_without_base_is_resource_error
      document = REXML::Document.new(wrap(include_xml("chunk.xml")))
      assert_raise(REXML::XInclude::ResourceError) do
        REXML::XInclude.expand(document, @resolver)
      end
    end

    # -- recursion -------------------------------------------------------

    def test_recursive_include_chain_is_detected
      put("file:///doc/a.xml",
          %Q{<a xmlns:xi="#{XI}"><xi:include href="b.xml"/></a>})
      put("file:///doc/b.xml",
          %Q{<b xmlns:xi="#{XI}"><xi:include href="a.xml"/></b>})
      assert_raise(REXML::XInclude::InclusionLoopError) do
        expand(wrap(include_xml("a.xml")))
      end
    end

    def test_same_resource_included_twice_is_not_a_loop
      put("file:///doc/chunk.xml", "<chunk/>")
      document = expand(wrap(include_xml("chunk.xml") +
                             include_xml("chunk.xml")))
      chunks = document.root.children.select { |c| c.name == "chunk" }
      assert_equal(2, chunks.size)
    end

    # -- xml:base --------------------------------------------------------

    def test_xml_base_on_include_changes_resolution_base
      put("file:///other/place/chunk.xml", "<chunk/>")
      inner = %Q{<xi:include xmlns:xi="#{XI}" href="chunk.xml" } +
              %Q{xml:base="file:///other/place/"/>}
      document = expand(wrap(inner))
      assert_equal("chunk", document.root.children.first.name)
    end

    def test_xml_base_on_ancestor_changes_resolution_base
      put("file:///other/chunk.xml", "<chunk/>")
      xml = %Q{<root xmlns:xi="#{XI}">} +
            %Q{<section xml:base="file:///other/">} +
            include_xml("chunk.xml") +
            %Q{</section></root>}
      document = expand(xml)
      section = document.root.children.first
      chunk = section.children.first
      assert_equal("chunk", chunk.name)
    end

    # -- API -------------------------------------------------------------

    def test_expand_returns_document
      document = REXML::Document.new(wrap(""))
      result = REXML::XInclude.expand(document, @resolver,
                                      base: "file:///doc/main.xml")
      assert_same(document, result)
    end

    def test_expand_accepts_block_resolver
      document = REXML::Document.new(wrap(include_xml("chunk.xml")))
      REXML::XInclude.expand(document, base: "file:///doc/main.xml") do |uri|
        "<chunk/>"
      end
      assert_equal("chunk", document.root.children.first.name)
    end

    def test_document_convenience_method
      put("file:///doc/chunk.xml", "<chunk/>")
      document = REXML::Document.new(wrap(include_xml("chunk.xml")))
      document.expand_xincludes(@resolver, base: "file:///doc/main.xml")
      assert_equal("chunk", document.root.children.first.name)
    end

    def test_resolver_must_be_supplied
      document = REXML::Document.new(wrap(""))
      assert_raise(ArgumentError) do
        REXML::XInclude.expand(document)
      end
    end

    def test_non_include_namespace_is_ignored
      xml = %Q{<root xmlns:other="urn:not-xinclude">} +
            %Q{<other:include href="x"/></root>}
      document = REXML::Document.new(xml)
      REXML::XInclude.expand(document, @resolver, base: "file:///doc/main.xml")
      assert_equal("include", document.root.children.first.name)
    end
  end
end
