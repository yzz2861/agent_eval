# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPQuotaTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  test "#setquota(quota_root, limit)" do
    with_fake_server do |server, imap|
      server.on "SETQUOTA", &:done_ok

      # integer arg
      imap.setquota "INBOX", 512
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",            rcvd_cmd.name
      assert_equal "INBOX (STORAGE 512)", rcvd_cmd.args

      # string arg
      imap.setquota "INBOX", "512"
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",            rcvd_cmd.name
      assert_equal "INBOX (STORAGE 512)", rcvd_cmd.args

      # empty quota root, null limit
      imap.setquota "", nil
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",            rcvd_cmd.name
      assert_equal '"" ()',               rcvd_cmd.args

      assert_raise_with_message(Net::IMAP::DataFormatError,
                                "512.0 is not a valid number64") do
        imap.setquota "INBOX", 512.0
      end
      assert_raise_with_message(Net::IMAP::DataFormatError,
                                '"512 620" is not a valid number64') do
        imap.setquota "INBOX", "512 620"
      end
    end
  end

  test "#setquota(quota_root, limit, **resource_limits)" do
    with_fake_server do |server, imap|
      server.on "SETQUOTA", &:done_ok

      # multiple resource limits
      imap.setquota "#user/alice", 512, message: 1000
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",                            rcvd_cmd.name
      assert_equal "#user/alice (STORAGE 512 MESSAGE 1000)", rcvd_cmd.args

      # keyword resource limits only, without a STORAGE limit
      imap.setquota "#user/alice", message: 1000
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",                 rcvd_cmd.name
      assert_equal "#user/alice (MESSAGE 1000)", rcvd_cmd.args

      # resource names are upcased, string keys are allowed
      imap.setquota "#user/alice", nil, "x-experimental" => 42
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",                        rcvd_cmd.name
      assert_equal "#user/alice (X-EXPERIMENTAL 42)", rcvd_cmd.args

      # no limits at all unsets the quota root's resource limits
      imap.setquota "#user/alice"
      rcvd_cmd = server.commands.pop
      assert_equal "SETQUOTA",        rcvd_cmd.name
      assert_equal "#user/alice ()",  rcvd_cmd.args

      # keyword limits are validated like the STORAGE limit
      assert_raise_with_message(Net::IMAP::DataFormatError,
                                "1.5 is not a valid number64") do
        imap.setquota "#user/alice", message: 1.5
      end

      # the STORAGE limit cannot be given twice
      assert_raise(ArgumentError) do
        imap.setquota "#user/alice", 512, storage: 100
      end
    end
  end

  test "#getquota returns every resource of the quota root" do
    with_fake_server do |server, imap|
      server.on "GETQUOTA" do |resp|
        resp.untagged 'QUOTA "#user/alice" (STORAGE 54 111 MESSAGE 42 1000 X-EXP 1 2)'
        resp.done_ok
      end

      quotas = imap.getquota("#user/alice")
      assert_equal 1, quotas.size
      quota = quotas.first
      assert_equal "#user/alice", quota.mailbox
      assert_equal "#user/alice", quota.quota_root
      assert_equal({ "STORAGE" => %w[54 111],
                     "MESSAGE" => %w[42 1000],
                     "X-EXP"   => %w[1 2] },
                   quota.resources)
      # STORAGE accessors remain compatible with the old single-resource API
      assert_equal "54",  quota.usage
      assert_equal "111", quota.quota
    end
  end

  test "#getquota with an empty resource list" do
    with_fake_server do |server, imap|
      server.on "GETQUOTA" do |resp|
        resp.untagged 'QUOTA "#user/alice" ()'
        resp.done_ok
      end

      quota = imap.getquota("#user/alice").first
      assert_equal({}, quota.resources)
      assert_nil quota.usage
      assert_nil quota.quota
    end
  end

  test "#getquotaroot returns every quota root with all of its resources" do
    with_fake_server do |server, imap|
      server.on "GETQUOTAROOT" do |resp|
        resp.untagged 'QUOTAROOT INBOX "#user/alice" "!partition/sda4"'
        resp.untagged 'QUOTA "#user/alice" (STORAGE 54 111 MESSAGE 42 1000)'
        resp.untagged 'QUOTA "!partition/sda4" (STORAGE 104 10923847)'
        resp.done_ok
      end

      result = imap.getquotaroot("INBOX")
      roots  = result.grep(Net::IMAP::MailboxQuotaRoot)
      quotas = result.grep(Net::IMAP::MailboxQuota)
      assert_equal 1, roots.size
      assert_equal "INBOX", roots.first.mailbox
      assert_equal ["#user/alice", "!partition/sda4"], roots.first.quotaroots
      assert_equal ["#user/alice", "!partition/sda4"],
                   quotas.map(&:quota_root)
      assert_equal({ "STORAGE" => %w[54 111], "MESSAGE" => %w[42 1000] },
                   quotas[0].resources)
      assert_equal({ "STORAGE" => %w[104 10923847] },
                   quotas[1].resources)
    end
  end

  test "QUOTA response with a malformed resource triple" do
    parser = Net::IMAP::ResponseParser.new
    # missing limit
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA \"#user/alice\" (STORAGE 10)\r\n")
    end
    # missing usage and limit
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA \"#user/alice\" (STORAGE)\r\n")
    end
    # trailing junk after a complete triple
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA \"#user/alice\" (STORAGE 10 20 30)\r\n")
    end
    # non-numeric usage
    assert_raise(Net::IMAP::ResponseParseError) do
      parser.parse("* QUOTA \"#user/alice\" (STORAGE lots 20)\r\n")
    end
  end
end
