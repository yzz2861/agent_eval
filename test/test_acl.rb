require 'common'

class TestACL < Net::SFTP::TestCase
  include Net::SFTP::Constants::ACE

  ATTRIBUTES = Net::SFTP::Protocol::V04::Attributes
  ACE_STRUCT = ATTRIBUTES::ACL
  ACL = Net::SFTP::ACL

  def ace(type, flag, mask, who)
    ACE_STRUCT.new(type, flag, mask, who)
  end

  def principal(user, groups=[])
    ACL::Principal.new(user, groups)
  end

  # -- inheritance (table-driven) ----------------------------------------

  # Each case describes a parent ACE, the type of object being created, and
  # the flag the inherited entry is expected to carry (nil meaning the
  # entry must not be inherited at all).
  INHERIT_CASES = [
    # a plain allow entry with no inherit flags is never inherited
    { :name => "no inherit flags, file child",
      :flag => 0, :child => :file, :expected_flag => nil },
    { :name => "no inherit flags, directory child",
      :flag => 0, :child => :directory, :expected_flag => nil },

    # FILE_INHERIT only reaches files, DIRECTORY_INHERIT only directories
    { :name => "file inherit, file child",
      :flag => Flag::FILE_INHERIT, :child => :file, :expected_flag => 0 },
    { :name => "file inherit, directory child",
      :flag => Flag::FILE_INHERIT, :child => :directory, :expected_flag => nil },
    { :name => "directory inherit, directory child",
      :flag => Flag::DIRECTORY_INHERIT, :child => :directory,
      :expected_flag => Flag::DIRECTORY_INHERIT },
    { :name => "directory inherit, file child",
      :flag => Flag::DIRECTORY_INHERIT, :child => :file, :expected_flag => nil },

    # INHERIT_ONLY is cleared on the child so the entry applies to it
    { :name => "inherit only, file child",
      :flag => Flag::FILE_INHERIT | Flag::INHERIT_ONLY, :child => :file,
      :expected_flag => 0 },
    { :name => "inherit only, directory child",
      :flag => Flag::DIRECTORY_INHERIT | Flag::INHERIT_ONLY, :child => :directory,
      :expected_flag => Flag::DIRECTORY_INHERIT },

    # NO_PROPAGATE_INHERIT stops further propagation through directories
    { :name => "no propagate, directory child",
      :flag => Flag::DIRECTORY_INHERIT | Flag::NO_PROPAGATE_INHERIT,
      :child => :directory, :expected_flag => 0 },
    { :name => "no propagate, file child",
      :flag => Flag::FILE_INHERIT | Flag::NO_PROPAGATE_INHERIT,
      :child => :file, :expected_flag => 0 },

    # unrelated flag bits (e.g. IDENTIFIER_GROUP) survive inheritance
    { :name => "group identifier preserved",
      :flag => Flag::FILE_INHERIT | Flag::IDENTIFIER_GROUP, :child => :file,
      :expected_flag => Flag::IDENTIFIER_GROUP },
  ]

  def test_inherit_flag_handling
    INHERIT_CASES.each do |c|
      parent = ace(Type::ACCESS_ALLOWED, c[:flag], Mask::READ_DATA, "alice")
      entries = ACL.inherit([parent], c[:child])

      if c[:expected_flag].nil?
        assert entries.empty?, "#{c[:name]}: expected no inherited entries"
      else
        assert_equal 1, entries.length, c[:name]
        assert_equal c[:expected_flag], entries.first.ace.flag, c[:name]
        # type, mask and who are carried over untouched
        assert_equal Type::ACCESS_ALLOWED, entries.first.ace.type, c[:name]
        assert_equal Mask::READ_DATA, entries.first.ace.mask, c[:name]
        assert_equal "alice", entries.first.ace.who, c[:name]
        # provenance: the entry remembers the ACE it was derived from
        assert_same parent, entries.first.source, c[:name]
      end
    end
  end

  def test_inherit_accepts_attributes_type_constants
    parent = ace(Type::ACCESS_ALLOWED, Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
                 Mask::READ_DATA, "alice")
    assert_equal 1, ACL.inherit([parent], ATTRIBUTES::T_REGULAR).length
    assert_equal 1, ACL.inherit([parent], ATTRIBUTES::T_DIRECTORY).length
  end

  def test_inherit_rejects_unknown_object_type
    assert_raises(ArgumentError) { ACL.inherit([], :symlink) }
  end

  def test_inherit_preserves_order_and_never_merges_entries
    parent = [
      ace(Type::ACCESS_DENIED,  Flag::FILE_INHERIT, Mask::WRITE_DATA, "alice"),
      ace(Type::ACCESS_ALLOWED, Flag::FILE_INHERIT, Mask::WRITE_DATA, "alice"),
    ]
    entries = ACL.inherit(parent, :file)
    assert_equal 2, entries.length
    assert_equal Type::ACCESS_DENIED,  entries[0].ace.type
    assert_equal Type::ACCESS_ALLOWED, entries[1].ace.type
    assert_same parent[0], entries[0].source
    assert_same parent[1], entries[1].source
  end

  def test_two_level_directory_inheritance
    # grandparent grants alice read+write, inheritable by both files and dirs
    grandparent = [
      ace(Type::ACCESS_ALLOWED, Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
          Mask::READ_DATA | Mask::WRITE_DATA, "alice"),
    ]

    child = ACL.inherit(grandparent, :directory)
    assert_equal 1, child.length
    # the child directory can still pass the entry on to its own children
    assert_equal Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT, child.first.ace.flag

    grandchild = ACL.inherit(child.map(&:ace), :directory)
    assert_equal 1, grandchild.length
    assert_equal Mask::READ_DATA | Mask::WRITE_DATA, grandchild.first.ace.mask
    # provenance chains back one level at a time
    assert_same child.first.ace, grandchild.first.source

    verdicts = ACL.evaluate(grandchild, principal("alice"),
                            Mask::READ_DATA | Mask::WRITE_DATA)
    assert_equal [:allowed, :allowed], verdicts.map(&:status)
  end

  def test_no_propagate_stops_at_second_level
    grandparent = [
      ace(Type::ACCESS_ALLOWED,
          Flag::DIRECTORY_INHERIT | Flag::NO_PROPAGATE_INHERIT,
          Mask::READ_DATA, "alice"),
    ]

    child = ACL.inherit(grandparent, :directory)
    assert_equal 1, child.length
    assert_equal 0, child.first.ace.flag

    # the entry applies to the child directory itself ...
    verdicts = ACL.evaluate(child, principal("alice"), Mask::READ_DATA)
    assert_equal :allowed, verdicts.first.status

    # ... but nothing propagates to the grandchild
    assert ACL.inherit(child.map(&:ace), :directory).empty?
  end

  # -- evaluation (table-driven) -----------------------------------------

  # Each case builds an ACL and a principal, requests a mask, and lists the
  # expected per-bit statuses (bits are reported in ascending order).
  def evaluate_cases
    [
    { :name => "simple allow",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:allowed] },

    { :name => "simple deny",
      :acl => [ace(Type::ACCESS_DENIED, 0, Mask::WRITE_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::WRITE_DATA,
      :expected => [:denied] },

    { :name => "first matching entry wins: deny before allow",
      :acl => [ace(Type::ACCESS_DENIED,  0, Mask::READ_DATA, "alice"),
               ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:denied] },

    { :name => "first matching entry wins: allow before deny",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice"),
               ace(Type::ACCESS_DENIED,  0, Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:allowed] },

    { :name => "mixed read/write mask evaluated bit by bit",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice"),
               ace(Type::ACCESS_DENIED,  0, Mask::WRITE_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA | Mask::WRITE_DATA,
      :expected => [:allowed, :denied] },

    { :name => "entries for other users do not apply",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "bob")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "group entry matches via IDENTIFIER_GROUP",
      :acl => [ace(Type::ACCESS_ALLOWED, Flag::IDENTIFIER_GROUP,
                   Mask::READ_DATA, "wheel")],
      :principal => principal("alice", ["wheel"]),
      :mask => Mask::READ_DATA,
      :expected => [:allowed] },

    { :name => "group entry does not match non-members",
      :acl => [ace(Type::ACCESS_ALLOWED, Flag::IDENTIFIER_GROUP,
                   Mask::READ_DATA, "wheel")],
      :principal => principal("alice", ["staff"]),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "EVERYONE@ matches any principal",
      :acl => [ace(Type::ACCESS_DENIED, 0, Mask::WRITE_DATA, "EVERYONE@")],
      :principal => principal("alice"),
      :mask => Mask::WRITE_DATA,
      :expected => [:denied] },

    { :name => "inherit-only entry is ignored on the object itself",
      :acl => [ace(Type::ACCESS_ALLOWED, Flag::INHERIT_ONLY,
                   Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "audit entries never decide access",
      :acl => [ace(Type::SYSTEM_AUDIT, 0, Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "unknown user identity is indeterminate, never allowed",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      :principal => principal(nil),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "unknown group identity is indeterminate, never allowed",
      :acl => [ace(Type::ACCESS_ALLOWED, Flag::IDENTIFIER_GROUP,
                   Mask::READ_DATA, "wheel")],
      :principal => principal("alice", nil),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "unresolvable special who is indeterminate",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "OWNER@")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "unknown ace type is indeterminate",
      :acl => [ace(0x7fffffff, 0, Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA,
      :expected => [:indeterminate] },

    { :name => "unrecognized permission bits are indeterminate",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, 0x40000000, "alice")],
      :principal => principal("alice"),
      :mask => 0x40000000,
      :expected => [:indeterminate] },

    { :name => "unaddressed bits are indeterminate, never default-allowed",
      :acl => [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA, "alice")],
      :principal => principal("alice"),
      :mask => Mask::READ_DATA | Mask::DELETE,
      :expected => [:allowed, :indeterminate] },
    ]
  end

  def test_evaluate_cases
    evaluate_cases.each do |c|
      verdicts = ACL.evaluate(c[:acl], c[:principal], c[:mask])
      assert_equal c[:expected], verdicts.map(&:status), c[:name]
    end
  end

  def test_evaluate_reports_one_verdict_per_requested_bit_in_order
    acl = [ace(Type::ACCESS_ALLOWED, 0, Mask::READ_DATA | Mask::EXECUTE, "alice")]
    verdicts = ACL.evaluate(acl, principal("alice"),
                            Mask::READ_DATA | Mask::WRITE_DATA | Mask::EXECUTE)
    assert_equal [Mask::READ_DATA, Mask::WRITE_DATA, Mask::EXECUTE],
                 verdicts.map(&:mask)
    assert_equal [:allowed, :indeterminate, :allowed], verdicts.map(&:status)
  end

  def test_evaluate_preserves_deciding_ace_and_inheritance_source
    parent = ace(Type::ACCESS_DENIED, Flag::FILE_INHERIT, Mask::WRITE_DATA, "alice")
    inherited = ACL.inherit([parent], :file)

    verdicts = ACL.evaluate(inherited, principal("alice"), Mask::WRITE_DATA)
    assert_equal :denied, verdicts.first.status
    assert_same inherited.first.ace, verdicts.first.ace
    assert_same parent, verdicts.first.source
  end

  def test_evaluate_without_matching_entry_has_no_source
    verdicts = ACL.evaluate([], principal("alice"), Mask::READ_DATA)
    assert_equal :indeterminate, verdicts.first.status
    assert_nil verdicts.first.ace
    assert_nil verdicts.first.source
  end
end
