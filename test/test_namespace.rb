# frozen_string_literal: false
require "core_assertions"

module REXMLTests
  class TestNamespace < Test::Unit::TestCase
    include Test::Unit::CoreAssertions
    include Helper::Fixture
    include REXML

    def setup
      @xsa_source = <<-EOL
        <?xml version="1.0"?>
        <?xsl stylesheet="blah.xsl"?>
        <!-- The first line tests the XMLDecl, the second tests PI.
        The next line tests DocType. This line tests comments. -->
        <!DOCTYPE xsa PUBLIC
          "-//LM Garshol//DTD XML Software Autoupdate 1.0//EN//XML"
          "http://www.garshol.priv.no/download/xsa/xsa.dtd">

        <xsa>
          <vendor id="blah">
            <name>Lars Marius Garshol</name>
            <email>larsga@garshol.priv.no</email>
            <url>http://www.stud.ifi.uio.no/~lmariusg/</url>
          </vendor>
        </xsa>
      EOL
    end

    def test_xml_namespace
      xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xml="http://www.w3.org/XML/1998/namespace" />
XML
      document = Document.new(xml)
      assert_equal("http://www.w3.org/XML/1998/namespace",
                   document.root.namespace("xml"))
    end

    def test_import_subtree_copy_preserves_expanded_names
      source = Document.new(<<-XML)
        <source xmlns:p="http://example.com/p" xmlns:d="http://example.com/default">
          <child p:a="1" type="p:Named" note="http://example.com/not-a-qname">
            <p:item d:b="2">text</p:item>
          </child>
        </source>
      XML
      target = Document.new(<<-XML)
        <target xmlns:p="http://target.example/p" xmlns:d="http://target.example/d"/>
      XML

      original = source.elements["//child"]
      expected_names = expanded_name_tuples(original)
      imported = target.root.import_subtree(original,
                                    qname_attributes: [["", "type"]])

      assert_not_same(original, imported)
      assert_equal("", imported.namespace)
      assert_equal("http://example.com/p",
                   imported.attributes.get_attribute_ns("http://example.com/p", "a").namespace)
      imported_item = imported.get_elements("*").first
      assert_equal("http://example.com/p", imported_item.namespace)
      assert_equal("http://example.com/default",
                   imported_item.attributes.get_attribute_ns("http://example.com/default", "b").namespace)
      assert_equal("p:Named", imported.attributes["type"])
      assert_equal("http://example.com/not-a-qname", imported.attributes["note"])
      assert_equal("http://example.com/p", original.namespace("p"))
      assert_equal("http://target.example/p", target.root.namespace("p"))
      assert_equal(expected_names, expanded_name_tuples(imported))
      assert_equal(expected_names, expanded_name_tuples(original))

      reparsed = Document.new(target.to_s)
      reparsed_child = reparsed.root[0]
      assert_equal("", reparsed_child.namespace)
      assert_equal("http://example.com/p",
                   reparsed_child.attributes.get_attribute_ns("http://example.com/p", "a").namespace)
      reparsed_item = reparsed_child.get_elements("*").first
      assert_equal("http://example.com/p", reparsed_item.namespace)
      assert_equal("http://example.com/default",
                   reparsed_item.attributes.get_attribute_ns("http://example.com/default", "b").namespace)
      assert_equal("p:Named", reparsed_child.attributes["type"])
      assert_equal("http://example.com/not-a-qname",
                   reparsed_child.attributes["note"])
      assert_equal(expected_names, expanded_name_tuples(reparsed_child))
    end

    def test_import_subtree_uses_empty_default_namespace_for_unprefixed_attributes
      source = Document.new('<source><child name="value"/></source>')
      target = Document.new('<target xmlns="http://target.example/"/>')

      imported = target.root.import_subtree(source.elements["//child"])

      assert_equal("", imported.namespace)
      assert_equal("", imported.attributes.get_attribute_ns("", "name").namespace)

      reparsed_child = Document.new(target.to_s).root[0]
      assert_equal("", reparsed_child.namespace)
      assert_equal("", reparsed_child.attributes.get_attribute_ns("", "name").namespace)
    end

    def test_import_subtree_preserves_reserved_xml_attribute_namespace
      source = Document.new('<source><child xml:lang="en"/></source>')
      target = Document.new('<target/>')

      imported = target.root.import_subtree(source.elements["//child"])

      assert_equal("http://www.w3.org/XML/1998/namespace",
                   imported.attributes.get_attribute_ns("http://www.w3.org/XML/1998/namespace", "lang").namespace)
      reparsed_child = Document.new(target.to_s).root.elements[1]
      assert_equal("http://www.w3.org/XML/1998/namespace",
                   reparsed_child.attributes.get_attribute_ns("http://www.w3.org/XML/1998/namespace", "lang").namespace)
    end

    def test_import_subtree_qname_whitelist_supports_multiple_tokens
      source = Document.new(<<-XML)
        <source xmlns:p="http://example.com/p" xmlns:q="http://example.com/q">
          <child types="p:First q:Second plain other:not:qname"/>
        </source>
      XML
      target = Document.new('<target xmlns:p="http://target.example/p"/>')

      imported = target.root.import_subtree(source.elements["//child"],
                                    qname_attributes: [{"" => "types"}])

      assert_equal("p:First q:Second plain other:not:qname",
                   imported.attributes["types"])
      reparsed_child = Document.new(target.to_s).root.elements[1]
      assert_equal("http://example.com/p",
                   reparsed_child.namespace("p"))
      assert_equal("http://example.com/q",
                   reparsed_child.namespace("q"))
    end

    def test_import_subtree_keeps_local_prefix_bindings
      source = Document.new(<<-XML)
        <source xmlns:p="http://outer.example/">
          <child>
            <p:outer/>
            <inner xmlns:p="http://inner.example/">
              <p:item p:a="1" type="p:InnerType"/>
            </inner>
          </child>
        </source>
      XML
      target = Document.new('<target xmlns:p="http://target.example/"/>')

      imported = target.root.import_subtree(source.elements["//child"],
                                    qname_attributes: [["", "type"]])
      child = imported
      outer, inner = *child.get_elements("*")

      assert_equal("http://outer.example/", outer.namespace)
      inner_item = inner.elements[1]
      assert_equal("http://inner.example/", inner_item.namespace)
      assert_equal("http://inner.example/",
                   inner_item.attributes.get_attribute_ns("http://inner.example/", "a").namespace)
      assert_equal("p:InnerType", inner_item.attributes["type"])

      reparsed = Document.new(target.to_s)
      reparsed_child = reparsed.root.elements[1]
      reparsed_outer, reparsed_inner = *reparsed_child.get_elements("*")
      reparsed_item = reparsed_inner.elements[1]
      assert_equal("http://outer.example/", reparsed_outer.namespace)
      assert_equal("http://inner.example/", reparsed_item.namespace)
      assert_equal("http://inner.example/",
                   reparsed_item.attributes.get_attribute_ns("http://inner.example/", "a").namespace)
      assert_equal("p:InnerType", reparsed_item.attributes["type"])
    end

    def test_import_subtree_move_removes_source_and_preserves_names
      source = Document.new(<<-XML)
        <source xmlns:p="http://source.example/">
          <child p:a="1">
            <p:item/>
          </child>
        </source>
      XML
      target = Document.new('<target xmlns:p="http://target.example/"/>')
      moved = source.elements["//child"]
      expected_names = expanded_name_tuples(moved)

      imported = target.root.import_subtree(moved, move: true)

      assert_same(moved, imported)
      assert_equal(0, source.root.each_element.count)
      assert_equal("http://source.example/", imported.namespace("p"))
      assert_equal("http://source.example/",
                   imported.attributes.get_attribute_ns("http://source.example/", "a").namespace)
      imported_item = imported.get_elements("*").first
      assert_equal("http://source.example/", imported_item.namespace)
      assert_equal(expected_names, expanded_name_tuples(imported))

      reparsed_source = Document.new(source.to_s)
      assert_equal(0, reparsed_source.root.each_element.count)
      reparsed_target = Document.new(target.to_s)
      reparsed_child = reparsed_target.root.elements[1]
      reparsed_item = reparsed_child.get_elements("*").first
      assert_equal("http://source.example/", reparsed_item.namespace)
      assert_equal(expected_names, expanded_name_tuples(reparsed_child))
    end

    def test_import_subtree_rejects_undefined_prefixes
      source_root = Element.new("source")
      child = Element.new("p:child")
      source_root << child
      target_root = Element.new("target")

      assert_raise(ArgumentError) do
        target_root.import_subtree(child)
      end
    end

    def test_import_deep_subtree_is_linear
      omit('Recursion too deep on JRuby') if RUBY_ENGINE == "jruby"

      assert_linear_performance([30, 100, 300, 1000], rehearsal: 10) do |depth|
        source = Document.new("<root xmlns:p='http://source.example/'>#{'<child>' * depth}<p:item/>#{'</child>' * depth}</root>")
        target = Document.new("<target xmlns:p='http://target.example/'/>")
        item = source.root.first
        item = item.first while item.first&.kind_of?(Element)
        target.root.import_subtree(item)
      end
    end

    def test_deep_element_namespace_linear
      omit('Recursion too deep on JRuby') if RUBY_ENGINE == "jruby"

      max_depth = 3000
      xml = <<~XML
        <root xmlns="one">#{'<a>' * max_depth + '</a>' * max_depth}</root>
      XML
      doc = Document.new(xml)
      prepare_element = ->(depth) do
        node = doc.root
        depth.times { node = node.first }
        node || raise
      end

      assert_linear_performance([30, 100, 300, 1000, 3000], rehearsal: 10) do |depth|
        elem = prepare_element.call(depth)
        elem.namespace
      end
    end

    def expanded_name_tuples(element)
      attributes = element.attributes.each_attribute.each_with_object([]) do |attribute, names|
        next if attribute.namespace_declaration?
        names << [attribute.namespace, attribute.name]
      end
      [
        element.namespace,
        element.name,
        attributes.sort,
        element.get_elements("*").map { |child| expanded_name_tuples(child) }
      ]
    end
    private :expanded_name_tuples
  end
end
