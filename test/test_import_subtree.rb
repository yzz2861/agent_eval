# frozen_string_literal: false
require "core_assertions"
require_relative "helper"

module REXMLTests
  class TestImportSubtree < Test::Unit::TestCase
    include REXML

    # Collects the expanded name (namespace URI, local name) of every element
    # and non-declaration attribute in document order.
    def expanded_names(element)
      names = []
      collect = lambda do |node|
        next unless node.is_a?(Element) && !node.is_a?(Document)
        names << [:element, node.namespace || "", node.name]
        node.attributes.each_attribute do |attribute|
          next if attribute.namespace_declaration?
          names << [:attribute, attribute.namespace || "", attribute.name]
        end
        node.each { |child| collect.call(child) }
      end
      collect.call(element)
      names
    end

    def assert_names_preserved(source_root, imported)
      expected = expanded_names(source_root)
      assert_equal(expected, expanded_names(imported))

      xml = imported.document.to_s
      assert_nothing_raised { REXML::Document.new(xml) }
      reparsed = REXML::Document.new(xml)
      reparsed_imported = locate_by_path(reparsed.root, child_index_path(imported))
      assert_equal(expected, expanded_names(reparsed_imported))
    end

    # Element-only child index path from the document element to +element+.
    def child_index_path(element)
      path = []
      node = element
      while node && node.parent
        parent = node.parent
        if parent.is_a?(Document)
          break
        end
        index = parent.elements.to_a.index { |sibling| sibling.equal?(node) }
        path << index
        node = node.parent
      end
      path.reverse
    end

    def locate_by_path(root, path)
      path.inject(root) { |node, index| node.elements.to_a[index] }
    end

    def test_conflicting_prefixed_element_and_attribute
      source = Document.new(<<~XML)
        <r xmlns:p="http://example/a">
          <p:child p:id="1" plain="z">
            <p:deep p:note="x"/>
          </p:child>
        </r>
      XML
      target = Document.new(<<~XML)
        <r xmlns:p="http://example/OTHER"><host/></r>
      XML

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["p:child"])

      assert_equal("ns1:child", imported.expanded_name)
      assert_equal("http://example/a", imported.namespace)
      assert_equal("http://example/a",
                   imported.attribute("ns1:id").namespace)
      assert_names_preserved(source.root.elements["p:child"], imported)
    end

    def test_prefix_reused_when_uris_match
      source = Document.new('<r xmlns:z="http://same"><z:a><z:b/></z:a></r>')
      target = Document.new('<r xmlns:z="http://same"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["z:a"])

      assert_equal("z:a", imported.expanded_name)
      assert_equal("z:b", imported.first.expanded_name)
      assert_not_include(imported.attributes.each_attribute
                           .map(&:expanded_name), "xmlns:z")
      assert_names_preserved(source.root.elements["z:a"], imported)
    end

    def test_conflicting_default_namespace_gets_new_prefix
      source = Document.new('<r xmlns="http://a"><child><deep/></child></r>')
      target = Document.new('<r xmlns="http://b"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["child"])

      assert_equal("http://a", imported.namespace)
      assert_equal("http://a", imported.first.namespace)
      assert_names_preserved(source.root.elements["child"], imported)
    end

    def test_unprefixed_attribute_never_uses_default_namespace
      source = Document.new('<r xmlns="http://a"><c id="1"/></r>')
      target = Document.new('<r xmlns="http://b"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["c"])

      assert_equal("", imported.attribute("id").namespace)
      assert_names_preserved(source.root.elements["c"], imported)
    end

    def test_namespace_shadowing_inside_subtree
      source = Document.new(<<~XML)
        <r xmlns:p="http://a" xmlns:q="http://b">
          <p:child p:x="1">
            <q:deep q:y="2"/>
            <p:again xmlns:p="http://c" p:w="3"/>
          </p:child>
        </r>
      XML
      target = Document.new('<r xmlns:p="http://OTHER"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["p:child"])

      assert_equal("http://a", imported.namespace)
      children = imported.elements.to_a
      assert_equal("http://b", children.first.namespace)
      again = children.last
      assert_equal("http://c", again.namespace)
      assert_equal("http://c", again.attributes.each_attribute
                               .find { |a| a.name == "w" }.namespace)
      assert_names_preserved(source.root.elements["p:child"], imported)
    end

    def test_default_namespace_undeclaration
      source = Document.new(<<~XML)
        <r xmlns="http://a">
          <child>
            <inner xmlns="">
              <leaf/>
            </inner>
          </child>
        </r>
      XML
      target = Document.new('<r xmlns="http://a"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["child"])

      assert_equal("http://a", imported.namespace)
      inner = imported.elements.to_a.first
      assert_equal("", inner.namespace)
      assert_equal("", inner.elements.to_a.first.namespace)
      assert_names_preserved(source.root.elements["child"], imported)
    end

    def test_move_detaches_and_reuses_source
      source = Document.new('<r xmlns:p="http://a"><p:c><p:g/></p:c></r>')
      target = Document.new('<r><host/></r>')
      original = source.root.elements["p:c"]

      moved = target.root.elements["host"]
        .import_subtree(original, mode: :move)

      assert_same(original, moved)
      assert_nil(source.root.elements["p:c"])
      assert_equal("host", moved.parent.expanded_name)
      assert_equal("http://a", moved.namespace)
      assert_equal("http://a", moved.first.namespace)
      assert_equal("http://a",
                   Document.new(target.to_s).root
                     .elements["host/*[1]"].first.namespace)
    end

    def test_copy_leaves_source_untouched
      source = Document.new('<r xmlns:p="http://a"><p:c p:x="1"/></r>')
      target = Document.new('<r><host/></r>')
      original = source.root.elements["p:c"]

      copied = target.root.elements["host"].import_subtree(original)

      assert_not_same(original, copied)
      assert_same(original, source.root.elements["p:c"])
      assert_equal("p:c", original.expanded_name)
      assert_equal("http://a", original.namespace)
      assert_names_preserved(original, copied)
    end

    def test_import_to_document
      source = Document.new('<r xmlns:p="http://a"><p:c/></r>')
      target = Document.new("")

      imported = target.import_subtree(source.root.elements["p:c"])

      assert_same(imported, target.root)
      assert_equal("http://a", imported.namespace)
      assert_equal("http://a", Document.new(target.to_s).root.namespace)
    end

    def test_qname_attribute_whitelist
      source = Document.new(<<~XML)
        <r xmlns:p="http://a" xmlns:x="http://x">
          <c x:type="p:Thing" label="p:NotAQualifiedName"/>
        </r>
      XML
      target = Document.new('<r xmlns:p="http://OTHER" xmlns:x="http://x"><host/></r>')

      imported = target.root.elements["host"].import_subtree(
        source.root.elements["c"],
        qname_attributes: ["{http://x}type"]
      )

      type_attribute = imported.attributes.each_attribute
        .find { |attribute| attribute.name == "type" }
      label_attribute = imported.attributes.each_attribute
        .find { |attribute| attribute.name == "label" }
      assert_equal("ns1:Thing", type_attribute.value)
      assert_equal("p:NotAQualifiedName", label_attribute.value)
    end

    def test_qname_attribute_whitelist_roundtrip
      source = Document.new(<<~XML)
        <r xmlns:p="http://a" xmlns:x="http://x">
          <c x:type="p:Thing"/>
        </r>
      XML
      target = Document.new('<r xmlns:p="http://OTHER" xmlns:x="http://x"><host/></r>')

      imported = target.root.elements["host"].import_subtree(
        source.root.elements["c"],
        qname_attributes: ["{http://x}type"]
      )

      reparsed_type = Document.new(target.to_s).root
        .elements["host/c"].attributes.each_attribute
        .find { |attribute| attribute.name == "type" }
      assert_equal("ns1:Thing", reparsed_type.value)
    end

    def test_qname_attribute_element_scoped_selector
      source = Document.new(<<~XML)
        <r xmlns:p="http://a" xmlns:x="http://x">
          <p:one x:type="p:One"/>
          <p:two x:type="p:Two"/>
        </r>
      XML
      target = Document.new('<r xmlns:p="http://OTHER" xmlns:x="http://x"><host/></r>')
      selectors = [["{http://a}one", "{http://x}type"]]

      one = target.root.elements["host"].import_subtree(
        source.root.elements["p:one"], qname_attributes: selectors)
      two = target.root.elements["host"].import_subtree(
        source.root.elements["p:two"], qname_attributes: selectors)

      assert_equal("ns1:One",
                   one.attributes.each_attribute
                     .find { |a| a.name == "type" }.value)
      assert_equal("p:Two",
                   two.attributes.each_attribute
                     .find { |a| a.name == "type" }.value)
    end

    def test_qname_list_attribute
      source = Document.new(<<~XML)
        <r xmlns:p="http://a" xmlns:x="http://x" xmlns:s="http://schema">
          <c x:schemaLocation="http://plain p:a.xsd s:local s-local.xsd"/>
        </r>
      XML
      target = Document.new('<r xmlns:p="http://OTHER" xmlns:x="http://x" xmlns:s="http://schema"><host/></r>')

      imported = target.root.elements["host"].import_subtree(
        source.root.elements["c"],
        qname_attributes: ["{http://x}schemaLocation"]
      )

      schema_location = imported.attributes.each_attribute
        .find { |a| a.name == "schemaLocation" }.value
      assert_equal("http://plain ns1:a.xsd s:local s-local.xsd",
                   schema_location)
    end

    def test_qname_selector_without_namespace
      source = Document.new('<r xmlns:p="http://a"><c type="p:Thing"/></r>')
      target = Document.new('<r xmlns:p="http://OTHER"><host/></r>')

      imported = target.root.elements["host"].import_subtree(
        source.root.elements["c"], qname_attributes: ["type"]
      )

      assert_equal("ns1:Thing",
                   imported.attributes.each_attribute
                     .find { |a| a.name == "type" }.value)
    end

    def test_colon_value_not_rewritten_without_whitelist
      source = Document.new('<r xmlns:p="http://a"><c type="p:Thing"/></r>')
      target = Document.new('<r xmlns:p="http://OTHER"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["c"])

      assert_equal("p:Thing", imported.attributes["type"])
    end

    def test_invalid_mode
      target = Document.new('<r><host/></r>')
      assert_raise(ArgumentError) do
        target.root.import_subtree(Element.new("c"), mode: :steal)
      end
    end

    def test_invalid_source
      target = Document.new('<r/>')
      assert_raise(ArgumentError) do
        target.root.import_subtree("not an element")
      end
    end

    def test_invalid_qname_selector
      target = Document.new('<r/>')
      assert_raise(ArgumentError) do
        target.root.import_subtree(Element.new("c"),
                                  qname_attributes: ["{no-brace"])
      end
      assert_raise(ArgumentError) do
        target.root.import_subtree(Element.new("c"),
                                  qname_attributes: [["c"]])
      end
    end

    def test_text_children_preserved
      source = Document.new('<r xmlns:p="http://a"><p:c>hello<p:b>world</p:b></p:c></r>')
      target = Document.new('<r xmlns:p="http://OTHER"><host/></r>')

      imported = target.root.elements["host"]
        .import_subtree(source.root.elements["p:c"])

      assert_equal("hello", imported.children.first.to_s)
      assert_equal("world", imported.elements.to_a.first.text)
      assert_names_preserved(source.root.elements["p:c"], imported)
    end
  end
end
