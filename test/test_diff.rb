# frozen_string_literal: false
require "rexml/diff"

module REXMLTests
  class DiffTester < Test::Unit::TestCase
    def parse(xml)
      REXML::Document.new(xml)
    end

    def diff(left, right, **options)
      REXML::Diff.compare(parse(left), parse(right), **options)
    end

    def test_identical_documents
      assert_equal([], diff("<root a='1'><child>text</child></root>",
                            "<root a='1'><child>text</child></root>"))
    end

    def test_identical_predicate
      assert do
        REXML::Diff.identical?(parse("<root/>"), parse("<root/>"))
      end
      assert_false(REXML::Diff.identical?(parse("<root/>"), parse("<root a='1'/>")))
    end

    def test_attribute_order_is_not_a_difference
      assert_equal([], diff("<root a='1' b='2'/>", "<root b='2' a='1'/>"))
    end

    def test_namespace_prefix_rename_is_not_a_difference
      left = "<a:root xmlns:a='http://example.com/ns' a:x='1'/>"
      right = "<b:root xmlns:b='http://example.com/ns' b:x='1'/>"
      assert_equal([], diff(left, right))
    end

    def test_default_namespace_matches_prefixed
      left = "<root xmlns='http://example.com/ns'><child/></root>"
      right = "<ns:root xmlns:ns='http://example.com/ns'><ns:child/></ns:root>"
      assert_equal([], diff(left, right))
    end

    def test_different_namespace_uri_is_a_difference
      left = "<a:root xmlns:a='http://example.com/one'/>"
      right = "<a:root xmlns:a='http://example.com/two'/>"
      differences = diff(left, right)
      assert_equal([:element_removed, :element_added],
                   differences.map(&:kind))
      assert_equal(["{http://example.com/one}root", nil],
                   differences.map(&:before))
    end

    def test_attribute_changed
      differences = diff("<root><item id='1' color='red'/></root>",
                         "<root><item id='1' color='blue'/></root>")
      assert_equal(1, differences.size)
      difference = differences[0]
      assert_equal(:attribute_changed, difference.kind)
      assert_equal("/root/item/@color", difference.path)
      assert_equal("red", difference.before)
      assert_equal("blue", difference.after)
    end

    def test_attribute_added_and_removed
      differences = diff("<root a='1' b='2'/>", "<root b='2' c='3'/>")
      assert_equal([[:attribute_removed, "/root/@a", "1", nil],
                    [:attribute_added, "/root/@c", nil, "3"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_namespaced_attribute
      left = "<root xmlns:n='http://example.com/ns' n:a='1'/>"
      right = "<root xmlns:n='http://example.com/ns' n:a='2'/>"
      differences = diff(left, right)
      assert_equal([:attribute_changed], differences.map(&:kind))
      assert_equal("/root/@{http://example.com/ns}a", differences[0].path)
    end

    def test_element_added_and_removed
      differences = diff("<root><a/><b/></root>", "<root><a/><c/></root>")
      assert_equal([[:element_removed, "/root/b"],
                    [:element_added, "/root/c"]],
                   differences.map {|d| [d.kind, d.path] })
    end

    def test_repeated_elements_get_positional_paths
      differences = diff("<root><item>1</item><item>2</item></root>",
                         "<root><item>1</item><item>3</item></root>")
      assert_equal([[:text_changed, "/root/item[2]/text()[1]", "2", "3"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_text_is_not_trimmed
      differences = diff("<root><a>x</a></root>", "<root><a> x </a></root>")
      assert_equal([[:text_changed, "/root/a/text()[1]", "x", " x "]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_mixed_content_text_position
      differences = diff("<root>before<child/>after</root>",
                         "<root>after<child/>before</root>")
      assert_equal([[:text_changed, "/root/text()[1]", "before", "after"],
                    [:text_changed, "/root/text()[2]", "after", "before"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_text_moved_across_element_changes_content_order
      differences = diff("<root>text<child/></root>",
                         "<root><child/>text</root>")
      assert_equal([[:content_order_changed, "/root",
                     "text() child", "child text()"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_identity_attributes_match_reordered_elements
      left = "<root><item id='1' v='a'/><item id='2' v='b'/></root>"
      right = "<root><item id='2' v='b'/><item id='1' v='c'/></root>"
      differences = diff(left, right, identity_attributes: ["id"])
      assert_equal([:attribute_changed], differences.map(&:kind))
      assert_equal("/root/item[1]/@v", differences[0].path)
      assert_equal("a", differences[0].before)
      assert_equal("c", differences[0].after)
    end

    def test_identity_attributes_detect_added_and_removed
      left = "<root><item id='1'/><item id='2'/></root>"
      right = "<root><item id='1'/><item id='3'/></root>"
      differences = diff(left, right, identity_attributes: ["id"])
      assert_equal([[:element_removed, "/root/item[2]"],
                    [:element_added, "/root/item[2]"]],
                   differences.map {|d| [d.kind, d.path] })
    end

    def test_conflicting_identity_keys_are_ambiguous
      left = "<root><item id='1' v='a'/><item id='1' v='b'/></root>"
      right = "<root><item id='1' v='c'/><item id='1' v='d'/></root>"
      differences = diff(left, right, identity_attributes: ["id"])
      assert_equal([:ambiguous_match], differences.map(&:kind))
      assert_equal("/root/item", differences[0].path)
      assert_equal([["1"], ["1"]], differences[0].before)
      assert_equal([["1"], ["1"]], differences[0].after)
    end

    def test_missing_identity_keys_are_ambiguous
      left = "<root><item id='1'/><item/></root>"
      right = "<root><item id='1'/><item/></root>"
      differences = diff(left, right, identity_attributes: ["id"])
      assert_equal([:ambiguous_match], differences.map(&:kind))
    end

    def test_comments_ignored_by_default
      assert_equal([], diff("<root><!--old--><a/></root>",
                            "<root><!--new--><a/></root>"))
    end

    def test_comments_compared_when_enabled
      differences = diff("<root><!--old--><a/></root>",
                         "<root><!--new--><a/></root>",
                         comments: true)
      assert_equal([[:comment_changed, "/root/comment()[1]", "old", "new"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_comment_added_when_enabled
      differences = diff("<root><a/></root>",
                         "<root><a/><!--note--></root>",
                         comments: true)
      assert_equal([[:comment_added, "/root/comment()[1]", nil, "note"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_documents_are_not_modified
      left = parse("<root a='1'><child>text</child></root>")
      right = parse("<root a='2'><child>other</child></root>")
      left_source = left.to_s
      right_source = right.to_s
      REXML::Diff.compare(left, right)
      assert_equal(left_source, left.to_s)
      assert_equal(right_source, right.to_s)
    end

    def test_difference_to_s
      difference = diff("<root a='1'/>", "<root a='2'/>")[0]
      assert_equal("attribute_changed at /root/@a: \"1\" -> \"2\"",
                   difference.to_s)
    end

    def test_root_element_difference
      differences = diff("<a/>", "<b/>")
      assert_equal([[:element_removed, "/a", "a", nil],
                    [:element_added, "/b", nil, "b"]],
                   differences.map {|d| [d.kind, d.path, d.before, d.after] })
    end

    def test_accepts_elements
      left = parse("<root><a/></root>").root
      right = parse("<root><a x='1'/></root>").root
      differences = REXML::Diff.compare(left, right)
      assert_equal([:attribute_added], differences.map(&:kind))
      assert_equal("/root/a/@x", differences[0].path)
    end
  end
end
