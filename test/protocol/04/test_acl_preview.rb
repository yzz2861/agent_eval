require 'common'

# Table-driven tests for the purely local ACL inheritance and access
# preview (Net::SFTP::Protocol::V04::ACLPreview). These tests only
# exercise client-side computation; the preview never replaces the
# server's final authorization decision.
class Protocol::V04::TestACLPreview < Net::SFTP::TestCase
  include Net::SFTP::Constants::ACE

  ACLPreview = Net::SFTP::Protocol::V04::ACLPreview
  Attributes = Net::SFTP::Protocol::V04::Attributes

  def ace(type, flag, mask, who)
    Attributes::ACL.new(type, flag, mask, who)
  end

  # -- inheritance ------------------------------------------------------

  # name, parent ace flag, child type, expected inherited flag (nil = not inherited)
  INHERIT_CASES = [
    ["file child inherits FILE_INHERIT entry and clears inherit flags",
      Flag::FILE_INHERIT, Attributes::T_REGULAR, 0],
    ["file child skips DIRECTORY_INHERIT-only entry",
      Flag::DIRECTORY_INHERIT, Attributes::T_REGULAR, nil],
    ["file child clears INHERIT_ONLY on inherited entry",
      Flag::FILE_INHERIT | Flag::INHERIT_ONLY, Attributes::T_REGULAR, 0],
    ["directory child inherits DIRECTORY_INHERIT entry with flags intact",
      Flag::DIRECTORY_INHERIT, Attributes::T_DIRECTORY, Flag::DIRECTORY_INHERIT],
    ["directory child skips FILE_INHERIT-only entry",
      Flag::FILE_INHERIT, Attributes::T_DIRECTORY, nil],
    ["directory child keeps both inherit flags when both are set",
      Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
      Attributes::T_DIRECTORY, Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT],
    ["NO_PROPAGATE_INHERIT clears inherit flags on the child copy",
      Flag::DIRECTORY_INHERIT | Flag::NO_PROPAGATE_INHERIT,
      Attributes::T_DIRECTORY, 0],
    ["INHERIT_ONLY and NO_PROPAGATE are both consumed on inheritance",
      Flag::DIRECTORY_INHERIT | Flag::INHERIT_ONLY | Flag::NO_PROPAGATE_INHERIT,
      Attributes::T_DIRECTORY, 0]
  ]

  def test_inherit_table
    INHERIT_CASES.each do |name, parent_flag, child_type, expected_flag|
      parent = [Attributes::ACL.new(Type::ACCESS_ALLOWED, parent_flag, Mask::READ_DATA, "alice")]
      inherited = ACLPreview.inherit(parent, child_type)

      if expected_flag.nil?
        assert_equal [], inherited, name
      else
        assert_equal 1, inherited.length, name
        assert_equal expected_flag, inherited.first.flag, name
        # type, mask and who are preserved verbatim on the copy
        assert_equal Type::ACCESS_ALLOWED, inherited.first.type, name
        assert_equal Mask::READ_DATA, inherited.first.mask, name
        assert_equal "alice", inherited.first.who, name
      end

      # the parent's entry is never mutated
      assert_equal parent_flag, parent.first.flag, name
    end
  end

  def test_inherit_should_propagate_through_two_directory_levels
    parent = [Attributes::ACL.new(Type::ACCESS_ALLOWED,
      Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
      Mask::READ_DATA | Mask::WRITE_DATA, "alice")]

    child = ACLPreview.inherit(parent, Attributes::T_DIRECTORY)
    assert_equal Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT, child.first.flag

    grandchild = ACLPreview.inherit(child, Attributes::T_DIRECTORY)
    assert_equal 1, grandchild.length
    assert_equal Mask::READ_DATA | Mask::WRITE_DATA, grandchild.first.mask
  end

  def test_inherit_should_stop_at_second_level_when_no_propagate_is_set
    parent = [Attributes::ACL.new(Type::ACCESS_ALLOWED,
      Flag::DIRECTORY_INHERIT | Flag::NO_PROPAGATE_INHERIT,
      Mask::READ_DATA, "alice")]

    child = ACLPreview.inherit(parent, Attributes::T_DIRECTORY)
    assert_equal 1, child.length

    grandchild = ACLPreview.inherit(child, Attributes::T_DIRECTORY)
    assert_equal [], grandchild
  end

  def test_inherit_should_never_merge_entries_for_the_same_principal
    parent = [
      Attributes::ACL.new(Type::ACCESS_DENIED, Flag::DIRECTORY_INHERIT, Mask::WRITE_DATA, "alice"),
      Attributes::ACL.new(Type::ACCESS_ALLOWED, Flag::DIRECTORY_INHERIT, Mask::READ_DATA, "alice")
    ]

    inherited = ACLPreview.inherit(parent, Attributes::T_DIRECTORY)
    assert_equal 2, inherited.length
    assert_equal Type::ACCESS_DENIED, inherited.first.type
    assert_equal Type::ACCESS_ALLOWED, inherited.last.type
  end

  def test_inherit_with_nil_acl_should_return_empty_array
    assert_equal [], ACLPreview.inherit(nil, Attributes::T_REGULAR)
  end

  # -- evaluation -------------------------------------------------------

  # name, acl, user, groups, mask, expected [verdict, ace_index] per bit
  EVALUATE_CASES = [
    ["first matching entry wins: deny before allow for the same principal",
      [Attributes::ACL.new(Type::ACCESS_DENIED, 0, Mask::READ_DATA, "alice"),
       Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      "alice", [], Mask::READ_DATA,
      [[ACLPreview::DENIED, 0]]],
    ["first matching entry wins: allow before deny for the same principal",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice"),
       Attributes::ACL.new(Type::ACCESS_DENIED, 0, Mask::READ_DATA, "alice")],
      "alice", [], Mask::READ_DATA,
      [[ACLPreview::ALLOWED, 0]]],
    ["mixed read/write bits are decided by different entries",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice"),
       Attributes::ACL.new(Type::ACCESS_DENIED, 0, Mask::WRITE_DATA, "alice")],
      "alice", [], Mask::READ_DATA | Mask::WRITE_DATA,
      [[ACLPreview::ALLOWED, 0], [ACLPreview::DENIED, 1]]],
    ["a bit no entry covers is indeterminate, not granted",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      "alice", [], Mask::READ_DATA | Mask::WRITE_DATA,
      [[ACLPreview::ALLOWED, 0], [ACLPreview::INDETERMINATE, nil]]],
    ["group entry matches any of the subject's groups",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, Flag::IDENTIFIER_GROUP, Mask::READ_DATA, "staff")],
      "alice", ["staff", "wheel"], Mask::READ_DATA,
      [[ACLPreview::ALLOWED, 0]]],
    ["group entry does not match when the subject lacks the group",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, Flag::IDENTIFIER_GROUP, Mask::READ_DATA, "staff")],
      "alice", ["wheel"], Mask::READ_DATA,
      [[ACLPreview::INDETERMINATE, nil]]],
    ["unknown principal still gets EVERYONE@ entries but nothing else",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice"),
       Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::WRITE_DATA, "EVERYONE@")],
      nil, [], Mask::READ_DATA | Mask::WRITE_DATA,
      [[ACLPreview::INDETERMINATE, nil], [ACLPreview::ALLOWED, 1]]],
    ["INHERIT_ONLY entries do not apply to the object itself",
      [Attributes::ACL.new(Type::ACCESS_ALLOWED, Flag::INHERIT_ONLY, Mask::READ_DATA, "alice")],
      "alice", [], Mask::READ_DATA,
      [[ACLPreview::INDETERMINATE, nil]]],
    ["audit and alarm entries are skipped during access evaluation",
      [Attributes::ACL.new(Type::SYSTEM_AUDIT, 0, Mask::READ_DATA, "alice"),
       Attributes::ACL.new(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      "alice", [], Mask::READ_DATA,
      [[ACLPreview::ALLOWED, 1]]],
    ["an unrecognized ACE type makes the bit indeterminate",
      [Attributes::ACL.new(99, 0, Mask::READ_DATA, "alice")],
      "alice", [], Mask::READ_DATA,
      [[ACLPreview::INDETERMINATE, 0]]]
  ]

  def test_evaluate_table
    EVALUATE_CASES.each do |name, acl, user, groups, mask, expected|
      decisions = ACLPreview.evaluate(acl,
        :user => user, :groups => groups, :mask => mask)

      assert_equal expected.length, decisions.length, name
      expected.zip(decisions).each_with_index do |(want, decision), i|
        verdict, ace_index = want
        assert_equal verdict, decision.verdict, "#{name} (bit #{i})"
        if ace_index
          assert_equal ace_index, decision.ace_index, "#{name} (bit #{i})"
          assert_equal acl[ace_index], decision.ace, "#{name} (bit #{i})"
        else
          assert_nil decision.ace_index, "#{name} (bit #{i})"
          assert_nil decision.ace, "#{name} (bit #{i})"
        end
      end
    end
  end

  def test_evaluate_should_report_unrecognized_permission_bits_as_indeterminate
    acl = [ace(Type::ACCESS_ALLOWED, 0, 0xffffffff, "alice")]
    decisions = ACLPreview.evaluate(acl, :user => "alice", :mask => 0x00200000)

    assert_equal 1, decisions.length
    assert decisions.first.indeterminate?
    assert_equal :unknown_mask_bit, decisions.first.reason
  end

  def test_evaluate_should_never_grant_by_default
    decisions = ACLPreview.evaluate([], :user => "alice", :mask => Mask::READ_DATA)
    assert decisions.first.indeterminate?
    assert_equal :no_matching_ace, decisions.first.reason

    decisions = ACLPreview.evaluate(nil, :user => "alice", :mask => Mask::READ_DATA)
    assert decisions.first.indeterminate?
  end

  def test_decision_predicates
    allowed = ACLPreview::Decision.new(Mask::READ_DATA, ACLPreview::ALLOWED, nil, nil, nil)
    assert allowed.allowed?
    assert !allowed.denied?
    assert !allowed.indeterminate?
  end

  # -- Attributes integration --------------------------------------------

  def test_attributes_should_delegate_inherit_and_preview
    attributes = Attributes.new(:type => Attributes::T_DIRECTORY, :acl => [
      ace(Type::ACCESS_ALLOWED, Flag::DIRECTORY_INHERIT, Mask::READ_DATA, "alice")
    ])

    inherited = attributes.inherit_acl(Attributes::T_DIRECTORY)
    assert_equal 1, inherited.length

    decisions = attributes.preview_access(:user => "alice", :mask => Mask::READ_DATA)
    assert decisions.first.allowed?
  end

  def test_v06_attributes_should_share_the_preview_api
    attributes = Net::SFTP::Protocol::V06::Attributes.new(:acl => [
      ace(Type::ACCESS_DENIED, 0, Mask::WRITE_DATA, "alice")
    ])

    decisions = attributes.preview_access(:user => "alice", :mask => Mask::WRITE_DATA)
    assert decisions.first.denied?
  end
end
