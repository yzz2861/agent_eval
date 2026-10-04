# frozen_string_literal: false

module REXMLTests
  class TestIdIndex < Test::Unit::TestCase
    DTD_XML = <<~XML
      <!DOCTYPE root [
        <!ATTLIST item uid ID #IMPLIED>
        <!ATTLIST note ref IDREFS #IMPLIED>
      ]>
      <root>
        <item uid="u1" xml:id="x1" id="plain1"/>
        <item uid="u2"/>
        <note ref="r1"/>
      </root>
    XML

    def parse(xml = DTD_XML)
      REXML::Document.new(xml)
    end

    def test_xml_id_is_indexed
      doc = parse
      assert_equal(doc.root.elements[1], doc.get_element_by_id("x1"))
    end

    def test_dtd_declared_id_is_indexed
      doc = parse
      assert_equal(doc.root.elements[1], doc.get_element_by_id("u1"))
      assert_equal(doc.root.elements[2], doc.get_element_by_id("u2"))
    end

    def test_plain_id_attribute_is_not_indexed
      doc = parse
      assert_nil(doc.get_element_by_id("plain1"))
    end

    def test_non_id_dtd_attribute_is_not_indexed
      doc = parse
      assert_nil(doc.get_element_by_id("r1"))
    end

    def test_id_declared_for_other_element_is_not_indexed
      doc = parse('<!DOCTYPE root [<!ATTLIST item uid ID #IMPLIED>]>' \
                  '<root><note uid="n1"/></root>')
      assert_nil(doc.get_element_by_id("n1"))
    end

    def test_unknown_id_returns_nil
      doc = parse
      assert_nil(doc.get_element_by_id("nosuch"))
    end

    def test_lookup_returns_the_identical_element
      doc = parse
      assert_same(doc.root.elements[1], doc.get_element_by_id("x1"))
    end

    def test_lookup_does_not_rescan_the_tree
      doc = parse
      root = doc.root
      def root.each_recursive(*)
        raise "query rescanned the tree"
      end
      def root.each_element(*)
        raise "query rescanned the tree"
      end
      assert_nothing_raised do
        doc.get_element_by_id("u1")
        doc.get_elements_by_id("u1")
      end
    end

    def test_add_attribute_updates_index
      doc = parse
      item = doc.root.elements[2]
      item.add_attribute("xml:id", "x2")
      assert_same(item, doc.get_element_by_id("x2"))
      item.attributes["uid"] = "u2b"
      assert_nil(doc.get_element_by_id("u2"))
      assert_same(item, doc.get_element_by_id("u2b"))
    end

    def test_add_attribute_object_updates_index
      doc = parse
      item = doc.root.elements[2]
      item.add_attribute(REXML::Attribute.new("xml:id", "x3"))
      assert_same(item, doc.get_element_by_id("x3"))
    end

    def test_delete_attribute_updates_index
      doc = parse
      item = doc.root.elements[1]
      item.delete_attribute("xml:id")
      assert_nil(doc.get_element_by_id("x1"))
      item.attributes.delete("uid")
      assert_nil(doc.get_element_by_id("u1"))
    end

    def test_assign_nil_deletes_and_updates_index
      doc = parse
      item = doc.root.elements[1]
      item.attributes["xml:id"] = nil
      assert_nil(doc.get_element_by_id("x1"))
    end

    def test_delete_all_updates_index
      doc = parse
      item = doc.root.elements[1]
      item.attributes.delete_all("uid")
      assert_nil(doc.get_element_by_id("u1"))
    end

    def test_normalized_value_change_updates_index
      doc = parse
      item = doc.root.elements[1]
      attribute = item.attributes.get_attribute("uid")
      attribute.normalized = "u1b"
      assert_nil(doc.get_element_by_id("u1"))
      assert_same(item, doc.get_element_by_id("u1b"))
    end

    def test_id_value_with_entity
      doc = parse('<root><a xml:id="a&amp;b"/></root>')
      assert_same(doc.root.elements[1], doc.get_element_by_id("a&b"))
      assert_nil(doc.get_element_by_id("a&amp;b"))
    end

    def test_remove_subtree_updates_index
      doc = parse
      item = doc.root.elements[1]
      item.remove
      assert_nil(doc.get_element_by_id("x1"))
      assert_nil(doc.get_element_by_id("u1"))
    end

    def test_add_subtree_updates_index
      doc = parse
      item = doc.root.elements[1]
      item.remove
      doc.root << item
      assert_same(item, doc.get_element_by_id("x1"))
      assert_same(item, doc.get_element_by_id("u1"))
    end

    def test_add_subtree_indexes_descendants
      doc = parse("<root/>")
      subtree = REXML::Document.new("<wrap><item uid=\"u9\"/></wrap>").root
      doc.root << subtree
      assert_nil(doc.get_element_by_id("u9")) # no DTD in doc
      subtree.elements[1].add_attribute("xml:id", "x9")
      assert_same(subtree.elements[1], doc.get_element_by_id("x9"))
    end

    def test_move_subtree_within_document_keeps_index
      doc = parse("<root><a><item xml:id=\"m1\"/></a><b/></root>")
      item = doc.root.elements["//item"]
      target = doc.root.elements["//b"]
      target << item
      assert_same(item, doc.get_element_by_id("m1"))
    end

    def test_insert_before_and_after_update_index
      doc = parse("<root><a/><b/></root>")
      a = doc.root.elements["//a"]
      b = doc.root.elements["//b"]
      e1 = REXML::Element.new("c")
      e1.add_attribute("xml:id", "c1")
      doc.root.insert_before(a, e1)
      assert_same(e1, doc.get_element_by_id("c1"))
      e2 = REXML::Element.new("d")
      e2.add_attribute("xml:id", "d1")
      doc.root.insert_after(b, e2)
      assert_same(e2, doc.get_element_by_id("d1"))
    end

    def test_replace_child_updates_index
      doc = parse("<root><a xml:id=\"old\"/></root>")
      old = doc.root.elements["//a"]
      replacement = REXML::Element.new("b")
      replacement.add_attribute("xml:id", "new")
      doc.root.replace_child(old, replacement)
      assert_nil(doc.get_element_by_id("old"))
      assert_same(replacement, doc.get_element_by_id("new"))
    end

    def test_cross_document_move
      xml = '<!DOCTYPE root [<!ATTLIST item uid ID #IMPLIED>]>' \
            '<root><item uid="u1" xml:id="x1"/></root>'
      source = parse(xml)
      target = parse('<!DOCTYPE root [<!ATTLIST item uid ID #IMPLIED>]>' \
                     '<root/>')
      item = source.root.elements[1]
      target.root << item
      assert_nil(source.get_element_by_id("x1"))
      assert_nil(source.get_element_by_id("u1"))
      assert_same(item, target.get_element_by_id("x1"))
      assert_same(item, target.get_element_by_id("u1"))
    end

    def test_cross_document_move_applies_new_document_dtd
      source = parse('<!DOCTYPE root [<!ATTLIST item uid ID #IMPLIED>]>' \
                     '<root><item uid="u1"/></root>')
      target = parse("<other/>")
      item = source.root.elements[1]
      target.root << item
      assert_nil(source.get_element_by_id("u1"))
      # The target document declares no ID attributes.
      assert_nil(target.get_element_by_id("u1"))
    end

    def test_duplicate_id_raises_conflict
      doc = parse('<root><a xml:id="dup"/><b xml:id="dup"/></root>')
      error = assert_raise(REXML::IDConflictError) do
        doc.get_element_by_id("dup")
      end
      assert_equal("dup", error.id)
      assert_equal(2, error.elements.size)
    end

    def test_duplicate_id_becomes_conflict_when_introduced
      doc = parse('<root><a xml:id="only"/></root>')
      doc.root.add_element("b", {"xml:id" => "only"})
      assert_raise(REXML::IDConflictError) do
        doc.get_element_by_id("only")
      end
    end

    def test_get_elements_by_id_returns_all_matches
      doc = parse('<root><a xml:id="dup"/><b xml:id="dup"/><c xml:id="uniq"/></root>')
      assert_equal(2, doc.get_elements_by_id("dup").size)
      assert_equal(1, doc.get_elements_by_id("uniq").size)
      assert_equal([], doc.get_elements_by_id("nosuch"))
    end

    def test_conflict_resolves_when_duplicate_removed
      doc = parse('<root><a xml:id="dup"/><b xml:id="dup"/></root>')
      survivor = doc.root.elements["//b"]
      doc.root.elements["//a"].remove
      assert_same(survivor, doc.get_element_by_id("dup"))
    end

    def test_doctype_added_after_parse
      doc = parse("<root><item uid=\"late\"/></root>")
      assert_nil(doc.get_element_by_id("late"))
      doctype = REXML::DocType.new("root")
      doctype.add(REXML::AttlistDecl.new(
                    ["item", {}, "<!ATTLIST item uid ID #IMPLIED>"]))
      doc.add(doctype)
      assert_same(doc.root.elements[1], doc.get_element_by_id("late"))
    end

    def test_attlist_added_to_existing_doctype
      doc = parse('<!DOCTYPE root []><root><item uid="late"/></root>')
      assert_nil(doc.get_element_by_id("late"))
      doc.doctype.add(REXML::AttlistDecl.new(
                        ["item", {}, "<!ATTLIST item uid ID #IMPLIED>"]))
      assert_same(doc.root.elements[1], doc.get_element_by_id("late"))
    end

    def test_doctype_removed_drops_dtd_ids_but_keeps_xml_id
      doc = parse
      doc.delete(doc.doctype)
      assert_nil(doc.get_element_by_id("u1"))
      assert_same(doc.root.elements[1], doc.get_element_by_id("x1"))
    end

    def test_attlist_decl_attribute_types
      doc = parse
      decl = doc.doctype.grep(REXML::AttlistDecl).first
      assert_equal({"uid" => "ID"}, decl.attribute_types)
    end
  end
end
