# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPQuotaTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  test "#setquota(quota_root, storage_limit) sets the STORAGE resource" do
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

  test "#setquota(quota_root, resource_limits) sets multiple resources" do
    with_fake_server do |server, imap|
      server.on "SETQUOTA", &:done_ok

      imap.setquota "#user/alice",
                          {"STORAGE" => 111, "MESSAGE" => 1000, "X-FOO" => "42"}
      assert_equal "SETQUOTA",                    server.commands.pop.name
      assert_equal "#user/alice (STORAGE 111 MESSAGE 1000 X-FOO 42)",
                   server.commands.pop.args

      imap.setquota "#user/alice",
                          [["MESSAGE", "1000"], ["STORAGE", 111]]
      assert_equal "#user/alice (MESSAGE 1000 STORAGE 111)",
                   server.commands.pop.args

      imap.setquota "INBOX", [["MESSAGE", 1000]]
      assert_equal "INBOX (MESSAGE 1000)", server.commands.pop.args

      assert_raise_with_message(ArgumentError, /listed more than once/) do
        imap.setquota "INBOX",
                            [["STORAGE", 1], ["STORAGE", 2]]
      end
      assert_empty server.commands

      [
        ["STORAGE"],
        ["STORAGE", 1, 2],
        [1, 1],
        "STORAGE",
      ].each do |bad|
        assert_raise_with_message(ArgumentError,
                                  /quota resources must be \[name, limit\] pairs/) do
          imap.setquota "INBOX", [bad]
        end
      end
      assert_empty server.commands

      assert_raise_with_message(Net::IMAP::DataFormatError,
                                "512.0 is not a valid number64") do
        imap.setquota "INBOX", 512.0
      end
      assert_empty server.commands
    end
  end
end
