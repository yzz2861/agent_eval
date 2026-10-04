# frozen_string_literal: false

require "rexml/diff"

module REXMLTests
  class TestDiff < Test::Unit::TestCase
    def compare(left, right, **options)
      REXML::Diff.compare(left, right, **options)
    end

    def test_identical_documents_have_no_differences
      assert_equal([], compare("<a x='1'>text</a>", "<a x='1'>text</a>"))
    end

    def test_attribute_order_is_not_a_difference
      left = "<a x='1' y='2' z='3'/>"
      right = "<a z='3' x='1' y='2'/>"
      assert_equal([], compare(left, right))
    end

    def test_namespace_prefix_rename_is_not_a_difference
      left = <<~XML
        <x:root xmlns:x="urn:a" xmlns="urn:default">
          <x:child x:attr="1" plain="2"/>
        </x:root>
      XML
      right = <<~XML
        <y:root xmlns:y="urn:a" xmlns="urn:default">
          <y:child y:attr="1" plain="2"/>
        </y:root>
      XML
      assert_equal([], compare(left, right))
    end

    def test_namespace_uri_change_is_a_difference
      left = '<x:root xmlns:x="urn:a"><x:child x:attr="1"/></x:root>'
      right = '<x:root xmlns:x="urn:b"><x:child x:attr="1"/></x:root>'
      differences = compare(left, right)
      kinds = differences.map(&:kind)
      assert_include(kinds, :element_name_changed)
      assert_include(kinds, :attribute_removed)
      assert_include(kinds, :attribute_added)
      name_change = differences.find {|d| d.kind == :element_name_changed}
      assert_equal("{urn:a}root", name_change.before)
      assert_equal("{urn:b}root", name_change.after)
    end

    def test_attribute_added_removed_and_changed
      left = "<a keep='1' change='2' drop='3'/>"
      right = "<a keep='1' change='4' new='5'/>"
      assert_equal(
        [
          [:attribute_changed, "/a/@change", "2", "4"],
          [:attribute_removed, "/a/@drop", "3", nil],
          [:attribute_added, "/a/@new", nil, "5"],
        ],
        compare(left, right).map {|d| [d.kind, d.path, d.before, d.after]},
      )
    end

    def test_element_name_change
      differences = compare("<a><old/></a>", "<a><new/></a>")
      assert_equal([:element_name_changed], differences.map(&:kind))
      assert_equal("/a/old", differences[0].path)
      assert_equal("old", differences[0].before)
      assert_equal("new", differences[0].after)
    end

    def test_child_order_matters
      differences = compare("<r><a/><b/></r>", "<r><b/><a/></r>")
      assert_equal([:element_name_changed, :element_name_changed],
                   differences.map(&:kind))
    end

    def test_node_added_and_removed
      differences = compare("<r><a/></r>", "<r><a/><b/></r>")
      assert_equal([[:node_added, "/r/b", nil, "<b>"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
      differences = compare("<r><a/><b/></r>", "<r><a/></r>")
      assert_equal([[:node_removed, "/r/b", "<b>", nil]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
    end

    def test_text_is_compared_exactly_without_trimming
      differences = compare("<a>x</a>", "<a> x </a>")
      assert_equal([[:text_changed, "/a/text()", "x", " x "]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
    end

    def test_text_position_in_mixed_content_is_significant
      left = "<p>Hello, <b>world</b>!</p>"
      right = "<p>Hello, <b>world</b>?</p>"
      differences = compare(left, right)
      assert_equal([[:text_changed, "/p/text()[2]", "!", "?"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
    end

    def test_repeated_siblings_get_stable_indexed_addresses
      left = "<root><item id='1'/><item id='2'/></root>"
      right = "<root><item id='1'/><item id='3'/></root>"
      differences = compare(left, right)
      assert_equal([[:attribute_changed, "/root/item[2]/@id", "2", "3"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
    end

    def test_identity_attributes_match_reordered_elements
      left = <<~XML
        <list>
          <item id="a" value="1"/>
          <item id="b" value="2"/>
        </list>
      XML
      right = <<~XML
        <list>
          <item id="b" value="2"/>
          <item id="a" value="1"/>
        </list>
      XML
      assert_equal([], compare(left, right, identity_attributes: {"item" => ["id"]}))
    end

    def test_identity_attributes_report_change_on_matched_element
      left = <<~XML
        <list>
          <item id="a" value="1"/>
          <item id="b" value="2"/>
        </list>
      XML
      right = <<~XML
        <list>
          <item id="b" value="3"/>
          <item id="a" value="1"/>
        </list>
      XML
      differences = compare(left, right, identity_attributes: {"item" => ["id"]})
      assert_equal([[:attribute_changed, "/list/item[2]/@value", "2", "3"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
    end

    def test_identity_attributes_added_and_removed
      left = <<~XML
        <list>
          <item id="a"/>
          <item id="b"/>
        </list>
      XML
      right = <<~XML
        <list>
          <item id="b"/>
          <item id="c"/>
        </list>
      XML
      differences = compare(left, right, identity_attributes: {"item" => ["id"]})
      assert_equal(
        [
          [:node_removed, "/list/item[1]", "<item>", nil],
          [:node_added, "/list/item[2]", nil, "<item>"],
        ],
        differences.map {|d| [d.kind, d.path, d.before, d.after]},
      )
    end

    def test_identity_attributes_array_form_applies_to_any_element
      left = "<list><entry id='a'/><entry id='b'/></list>"
      right = "<list><entry id='b'/><entry id='a'/></list>"
      assert_equal([], compare(left, right, identity_attributes: ["id"]))
    end

    def test_conflicting_identity_keys_raise_instead_of_guessing
      left = <<~XML
        <list>
          <item id="a" value="1"/>
          <item id="a" value="2"/>
        </list>
      XML
      right = "<list><item id='a' value='1'/></list>"
      assert_raise(REXML::Diff::AmbiguousIdentityError) do
        compare(left, right, identity_attributes: {"item" => ["id"]})
      end
    end

    def test_comments_are_ignored_by_default
      left = "<r><!--old--><a/></r>"
      right = "<r><!--new--><a/></r>"
      assert_equal([], compare(left, right))
      assert_equal([], compare("<r><a/></r>", "<r><!--added--><a/></r>"))
    end

    def test_comments_participate_when_option_enabled
      left = "<r><!--old--><a/></r>"
      right = "<r><!--new--><a/></r>"
      differences = compare(left, right, comments: true)
      assert_equal([[:comment_changed, "/r/comment()", "old", "new"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after]})
    end

    def test_documents_are_not_modified
      left = REXML::Document.new("<r a='1'><c>text</c></r>")
      right = REXML::Document.new("<r a='2'><c>other</c><d/></r>")
      left_before = left.to_s
      right_before = right.to_s
      compare(left, right)
      assert_equal(left_before, left.to_s)
      assert_equal(right_before, right.to_s)
    end

    def test_accepts_strings_documents_and_elements
      string = "<a x='1'/>"
      document = REXML::Document.new(string)
      element = document.root
      assert_equal([], compare(string, document))
      assert_equal([], compare(document, element))
      assert_equal([], compare(element, string))
    end
  end
end
