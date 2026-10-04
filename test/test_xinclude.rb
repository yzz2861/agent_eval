# -*- coding: utf-8 -*-
# frozen_string_literal: false

require "stringio"
require_relative "helper"

module REXMLTests
  class TestXInclude < Test::Unit::TestCase
    XI_NS = "http://www.w3.org/2001/XInclude"

    def setup
      @resources = {}
      @requested_uris = []
      add("a.xml", <<~XML)
        <included-root xmlns:ex="http://example/ns">
          <child ex:name="one">text</child>
          <sibling/>
        </included-root>
      XML
      add("b.xml", nested_include("a.xml"))
      add("cycle-a.xml", nested_include("cycle-b.xml"))
      add("cycle-b.xml", nested_include("cycle-a.xml"))
      add("default.xml", <<~XML)
        <root xmlns="http://example/default"><child/></root>
      XML
      add("rebound.xml", <<~XML)
        <root xmlns:p="http://outer">
          <item xmlns:p="http://inner" p:value="yes"/>
        </root>
      XML
      add("rebound-descendant.xml", <<~XML)
        <root xmlns:p="http://outer">
          <item><inner xmlns:p="http://inner" p:value="yes"/></item>
          <other p:value="no"/>
        </root>
      XML
      add("with-base.xml", <<~XML)
        <root xml:base="dir/source.xml">
          <child xml:base="child.xml"/>
        </root>
      XML
      add("malformed.xml", "<root><unclosed>")
      add("plain.txt", "a < b & c")
    end

    private

    def add(name, content)
      @resources["http://example/base/#{name}"] = content
    end

    def nested_include(href)
      %Q(<root xmlns:xi="#{XI_NS}"><xi:include href="#{href}"/></root>)
    end

    def include_xml(href, attributes = "", inner = "")
      %Q(<root xmlns:xi="#{XI_NS}"><xi:include href="#{href}" #{attributes}>#{inner}</xi:include></root>)
    end

    def include_fragment(href)
      %Q(<xi:include xmlns:xi="#{XI_NS}" href="#{href}"/>)
    end

    def fallback_xml(content)
      %Q(<xi:fallback>#{content}</xi:fallback>)
    end

    def expand(xml, base: "http://example/base/main.xml")
      document = REXML::Document.new(xml)
      document.xinclude(base: base) do |uri|
        @requested_uris << uri
        @resources.fetch(uri) do
          raise REXML::XInclude::ResourceMissing, uri
        end
      end
      document
    end

    public

    def test_expands_xml_include
      document = expand(include_xml("a.xml"))

      assert_equal(["child", "sibling"],
                   document.root.elements.map(&:expanded_name))
      assert_equal("one", document.root.elements["//child"].attribute("ex:name").value)
    end

    def test_resolves_relative_uri_from_xml_base
      document = expand(<<~XML)
        <root xmlns:xi="#{XI_NS}" xml:base="http://example/base/main.xml">
          <xi:include href="a.xml"/>
        </root>
      XML

      assert_equal(["http://example/base/a.xml"], @requested_uris)
      assert_equal("child", document.root.elements.first.expanded_name)
    end

    def test_adds_xml_base_to_included_elements
      document = expand(include_xml("a.xml"))
      child = document.root.elements["//child"]

      assert_equal("http://example/base/a.xml", child.attribute("xml:base").value)
    end

    def test_preserves_xml_base_inside_included_document
      document = expand(include_xml("with-base.xml"))
      child = document.root.elements["//child"]

      assert_equal("http://example/base/dir/child.xml",
                   child.attribute("xml:base").value)
    end

    def test_preserves_default_namespace
      document = expand(include_xml("default.xml"))
      child = document.root.elements["//child"]

      assert_equal("http://example/default", child.namespace)
      assert_equal("http://example/default", child.attribute("xmlns").value)
    end

    def test_resets_default_namespace_when_included_document_has_none
      document = expand(<<~XML)
        <root xmlns="http://destination" xmlns:xi="#{XI_NS}">
          <xi:include href="a.xml"/>
        </root>
      XML
      child = document.root.elements["//child"]

      assert_equal("", child.namespace)
      assert_equal("", child.attribute("xmlns").value)
    end

    def test_preserves_namespace_prefixes_used_in_descendants
      document = expand(include_xml("a.xml"))

      assert_equal("http://example/ns",
                   document.root.elements["//child"].namespace("ex"))
    end

    def test_preserves_locally_rebound_namespace_prefix
      document = expand(include_xml("rebound.xml"))
      item = document.root.elements["//item"]

      assert_equal("http://inner", item.namespace("p"))
      assert_equal("http://inner", item.attribute("xmlns:p").value)
    end

    def test_preserves_prefix_when_destination_uses_different_namespace
      document = expand(<<~XML)
        <root xmlns:ex="http://destination" xmlns:xi="#{XI_NS}">
          <xi:include href="a.xml"/>
        </root>
      XML
      child = document.root.elements["//child"]

      assert_equal("http://example/ns", child.namespace("ex"))
      assert_equal("http://example/ns", child.attribute("xmlns:ex").value)
    end

    def test_keeps_locally_rebound_prefix_local
      document = expand(<<~XML)
        <root xmlns:p="http://destination" xmlns:xi="#{XI_NS}">
          <xi:include href="rebound-descendant.xml"/>
        </root>
      XML
      other = document.root.elements["//other"]

      assert_equal("http://outer", other.namespace("p"))
      assert_equal("http://outer", other.attribute("xmlns:p").value)
    end

    def test_expands_text_include_as_text
      document = expand(include_xml("plain.txt", 'parse="text"'))

      assert_equal("a < b & c", document.root.text)
      assert_match("a &lt; b &amp; c", document.to_s)
    end

    def test_accepts_io_from_resolver
      document = REXML::Document.new(include_xml("plain.txt", 'parse="text"'))
      document.xinclude(base: "http://example/base/main.xml") do
        StringIO.new(@resources["http://example/base/plain.txt"])
      end

      assert_equal("a < b & c", document.root.text)
    end

    def test_uses_fallback_when_resource_is_missing
      document = expand(include_xml("missing.xml",
                                    "",
                                    fallback_xml("<fallback-child/>")))

      assert_equal("fallback-child", document.root.first.expanded_name)
    end

    def test_expands_include_inside_used_fallback
      document = expand(include_xml("missing.xml",
                                    "",
                                    fallback_xml(include_fragment("a.xml"))))

      assert_equal("child", document.root.elements.first.expanded_name)
    end

    def test_missing_resource_without_fallback_is_not_swallowed
      assert_raise(REXML::XInclude::ResourceMissing) do
        expand(include_xml("missing.xml"))
      end
    end

    def test_malformed_xml_error_is_not_swallowed_by_fallback
      assert_raise(REXML::ParseException) do
        expand(include_xml("malformed.xml",
                           "",
                           fallback_xml("<fallback-child/>")))
      end
    end

    def test_resolver_error_is_not_swallowed_by_fallback
      @resources.delete("http://example/base/a.xml")
      document = REXML::Document.new(include_xml("a.xml",
                                                 "",
                                                 fallback_xml("<fallback-child/>")))
      assert_raise(RuntimeError) do
        document.xinclude(base: "http://example/base/main.xml") do |uri|
          @requested_uris << uri
          raise "resolver failure"
        end
      end
    end

    def test_rejects_xpointer_attribute
      assert_raise(REXML::XInclude::UnsupportedXPointer) do
        expand(include_xml("a.xml", 'xpointer="/root/*"'))
      end
    end

    def test_rejects_xpointer_fragment_in_href
      assert_raise(REXML::XInclude::UnsupportedXPointer) do
        expand(include_xml("a.xml#xpointer(/root/*)"))
      end
    end

    def test_rejects_unsupported_parse_value
      assert_raise(REXML::XInclude::Error) do
        expand(include_xml("a.xml", 'parse="binary"'))
      end
    end

    def test_unsupported_parse_value_is_not_swallowed_by_fallback
      assert_raise(REXML::XInclude::Error) do
        expand(include_xml("a.xml",
                           'parse="binary"',
                           fallback_xml("<fallback-child/>")))
      end
    end

    def test_rejects_xpointer_even_when_fallback_exists
      assert_raise(REXML::XInclude::UnsupportedXPointer) do
        expand(include_xml("a.xml",
                           'xpointer="/root/*"',
                           fallback_xml("<fallback-child/>")))
      end
    end

    def test_detects_recursive_include_chain
      assert_raise(REXML::XInclude::RecursiveInclude) do
        expand(include_xml("cycle-a.xml"))
      end
    end

    def test_nested_relative_uri_uses_including_document_base
      document = expand(include_xml("b.xml"))

      assert_equal(%w[http://example/base/b.xml http://example/base/a.xml],
                   @requested_uris)
      assert_equal("child", document.root.elements.first.expanded_name)
    end

    def test_relative_include_without_base_is_rejected
      assert_raise(REXML::XInclude::Error) do
        expand(include_xml("a.xml"), base: nil)
      end
    end

    def test_does_not_expand_without_resolver
      assert_raise(ArgumentError) do
        REXML::XInclude.expand(REXML::Document.new(include_xml("a.xml")))
      end
    end
  end
end
