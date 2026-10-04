# frozen_string_literal: false

module REXMLTests
  class TestIDIndex < Test::Unit::TestCase
    def test_dtd_id_and_xml_id_are_indexed
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ATTLIST item dtd-id ID #IMPLIED>
          <!ATTLIST item fixed-id ID #FIXED "fixed">
        ]>
        <root>
          <item id="ignored" dtd-id="declared" xml:id="xml"/>
        </root>
      XML

      item = doc.root.elements[1]
      assert_equal(item, doc.element_by_id("declared"))
      assert_equal(item, doc.element_by_id("xml"))
      assert_equal(item, doc.element_by_id("fixed"))
      assert_equal(item, doc.get_element_by_id("declared"))
      assert_nil(doc.element_by_id("ignored"))
    end

    def test_duplicate_id_is_explicitly_reported
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ATTLIST item id ID #IMPLIED>
        ]>
        <root>
          <item id="same"/>
          <item id="same"/>
        </root>
      XML

      assert_equal(["same"], doc.id_index.conflicts)
      assert_equal(2, doc.id_index.elements_for("same").size)
      error = assert_raise(REXML::DuplicateIDError) do
        doc.element_by_id("same")
      end
      assert_include(error.message, "duplicate ID")
    end

    def test_attribute_changes_update_index
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ATTLIST item id ID #IMPLIED>
        ]>
        <root><item id="before"/></root>
      XML
      item = doc.root.elements[1]

      item.attributes["id"] = "after"
      assert_nil(doc.element_by_id("before"))
      assert_equal(item, doc.element_by_id("after"))

      item.attributes["id"] = nil
      assert_nil(doc.element_by_id("after"))
    end

    def test_renaming_attribute_object_updates_index
      doc = REXML::Document.new('<root><item xml:id="before"/></root>')
      item = doc.root.elements[1]
      attribute = item.attributes.get_attribute("xml:id")

      attribute.name = "other"
      assert_nil(doc.element_by_id("before"))
      assert_equal(["other"], item.attributes.to_a.map(&:expanded_name))

      attribute.name = "xml:id"
      assert_equal(item, doc.element_by_id("before"))
    end

    def test_adding_and_removing_subtree_updates_index
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ATTLIST item id ID #IMPLIED>
        ]>
        <root/>
      XML
      item = REXML::Element.new("item")
      item.add_attribute("id", "child")

      doc.root << item
      assert_equal(item, doc.element_by_id("child"))

      item.remove
      assert_nil(doc.element_by_id("child"))
    end

    def test_moving_subtree_within_document_preserves_index
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ATTLIST item id ID #IMPLIED>
        ]>
        <root><a><item id="moving"/></a><b/></root>
      XML
      item = doc.elements["//item"]
      target = doc.elements["//b"]

      target << item
      assert_equal(item, doc.element_by_id("moving"))
      assert_equal(target, item.parent)
    end

    def test_moving_subtree_between_documents_rebinds_index
      source = REXML::Document.new(<<~XML)
        <root><item xml:id="shared"/></root>
      XML
      target = REXML::Document.new("<root/>")
      item = source.elements["//item"]

      target.root << item
      assert_nil(source.element_by_id("shared"))
      assert_equal(item, target.element_by_id("shared"))
    end

    def test_adding_dtd_declaration_rebuilds_index
      doc = REXML::Document.new('<root><item id="declared"/></root>')
      assert_nil(doc.element_by_id("declared"))

      doctype = REXML::DocType.new("root")
      declaration = REXML::AttlistDecl.new([
        "item",
        {},
        "<!ATTLIST item id ID #IMPLIED>"
      ])
      doctype << declaration
      doc << doctype

      assert_equal(doc.elements["//item"], doc.element_by_id("declared"))
    end

    def test_xpath_id_uses_index
      doc = REXML::Document.new('<root><item xml:id="one"/></root>')
      assert_equal([doc.elements["//item"]],
                   REXML::XPath.match(doc, 'id("one")'))
      assert_equal([], REXML::XPath.match(doc, 'id("missing")'))
    end
  end
end
