# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPMoveFallbackTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  test "uses atomic UID MOVE when the server supports MOVE" do
    with_fake_server(select: "INBOX",
                     extensions: %i[MOVE UIDPLUS]) do |server, imap|
      server.on "UID MOVE" do |cmd|
        cmd.untagged "OK [COPYUID 38505 4:6 101:103] Moved"
        cmd.done_ok
      end
      copyuid = imap.uid_move_fallback(4..6, "Archive")
      cmd = server.commands.pop
      assert_equal ["UID MOVE", "4:6 Archive"], [cmd.name, cmd.args]
      assert_equal({4 => 101, 5 => 102, 6 => 103}, copyuid.uid_mapping)
      assert server.commands.empty?
    end
  end

  test "falls back to UID COPY, UID STORE, and UID EXPUNGE with UIDPLUS only" do
    with_fake_server(select: "INBOX",
                     extensions: %i[UIDPLUS]) do |server, imap|
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 4:6 101:103"
      end
      server.on "UID STORE", &:done_ok
      server.on "UID EXPUNGE" do |cmd|
        cmd.untagged "2 EXPUNGE"
        cmd.untagged "2 EXPUNGE"
        cmd.untagged "2 EXPUNGE"
        cmd.done_ok
      end
      copyuid = imap.uid_move_fallback(4..6, "Archive")
      assert_equal({4 => 101, 5 => 102, 6 => 103}, copyuid.uid_mapping)
      copy, store, expunge = 3.times.map { server.commands.pop }
      assert_equal ["UID COPY", "4:6 Archive"], [copy.name, copy.args]
      assert_equal ["UID STORE", "4:6 +FLAGS (\\Deleted)"],
                   [store.name, store.args]
      assert_equal ["UID EXPUNGE", "4:6"], [expunge.name, expunge.args]
      assert server.commands.empty?
    end
  end

  test "raises instead of degrading to EXPUNGE without MOVE or UIDPLUS" do
    with_fake_server(select: "INBOX", extensions: []) do |server, imap|
      server.on "EXPUNGE", &:fail_no_command
      error = assert_raise(Net::IMAP::Error) do
        imap.uid_move_fallback(4..6, "Archive")
      end
      assert_not_kind_of Net::IMAP::MoveFallbackError, error
      assert server.commands.empty? # no command was sent, especially EXPUNGE
    end
  end

  test "failure after COPY reports completed stages and the UID mapping" do
    with_fake_server(select: "INBOX",
                     extensions: %i[UIDPLUS]) do |server, imap|
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 4:6 101:103"
      end
      server.on "UID STORE" do |cmd|
        cmd.fail_no "cannot store flags"
      end
      error = assert_raise(Net::IMAP::MoveFallbackError) do
        imap.uid_move_fallback(4..6, "Archive")
      end
      assert_equal :store, error.stage
      assert_equal %i[copy], error.completed_stages
      assert error.copied?
      assert_equal({4 => 101, 5 => 102, 6 => 103}, error.uid_mapping)
      assert_equal "Archive", error.mailbox
      assert_kind_of Net::IMAP::NoResponseError, error.cause
      assert_equal "UID COPY",  server.commands.pop.name
      assert_equal "UID STORE", server.commands.pop.name
      assert server.commands.empty? # UID EXPUNGE was never sent
    end
  end

  test "failure during UID EXPUNGE reports copy and store as completed" do
    with_fake_server(select: "INBOX",
                     extensions: %i[UIDPLUS]) do |server, imap|
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 4:6 101:103"
      end
      server.on "UID STORE", &:done_ok
      server.on "UID EXPUNGE" do |cmd|
        cmd.fail_no "cannot expunge"
      end
      error = assert_raise(Net::IMAP::MoveFallbackError) do
        imap.uid_move_fallback(4..6, "Archive")
      end
      assert_equal :expunge, error.stage
      assert_equal %i[copy store], error.completed_stages
      assert_equal({4 => 101, 5 => 102, 6 => 103}, error.uid_mapping)
      assert_kind_of Net::IMAP::NoResponseError, error.cause
      assert server.commands.empty?
    end
  end

  test "aborts when UIDVALIDITY changes before the store stage" do
    with_fake_server(select: "INBOX",
                     extensions: %i[UIDPLUS]) do |server, imap|
      server.on "UID COPY" do |cmd|
        cmd.untagged "OK [UIDVALIDITY 12345] mailbox was re-selected"
        cmd.done_ok code: "COPYUID 38505 4:6 101:103"
      end
      error = assert_raise(Net::IMAP::MoveFallbackError) do
        imap.uid_move_fallback(4..6, "Archive")
      end
      assert_equal :store, error.stage
      assert_equal %i[copy], error.completed_stages
      assert_match(/UIDVALIDITY/, error.message)
      assert_equal "UID COPY", server.commands.pop.name
      assert server.commands.empty? # UID STORE was never sent
    end
  end

  test "aborts when the mailbox selection is closed before the store stage" do
    with_fake_server(select: "INBOX",
                     extensions: %i[UIDPLUS]) do |server, imap|
      server.on "UID COPY" do |cmd|
        cmd.untagged "OK [CLOSED] mailbox was closed"
        cmd.done_ok code: "COPYUID 38505 4:6 101:103"
      end
      error = assert_raise(Net::IMAP::MoveFallbackError) do
        imap.uid_move_fallback(4..6, "Archive")
      end
      assert_equal :store, error.stage
      assert_equal %i[copy], error.completed_stages
      assert_match(/selection/, error.message)
      assert_equal "UID COPY", server.commands.pop.name
      assert server.commands.empty? # UID STORE was never sent
    end
  end

  # Acceptance: the mailbox already contains other messages (UIDs 3 and 7)
  # that were flagged \Deleted by another session.  Moving UIDs 4:6 must
  # expunge only those UIDs; a plain EXPUNGE would destroy 3 and 7 as well.
  test "does not expunge other messages already marked \\Deleted" do
    with_fake_server(select: "INBOX",
                     extensions: %i[UIDPLUS]) do |server, imap|
      server.on "EXPUNGE" do |cmd|
        # A full-mailbox EXPUNGE would also remove UIDs 3 and 7 here.
        cmd.fail_bad "client must never send EXPUNGE for a fallback move"
      end
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 4:6 101:103"
      end
      server.on "UID STORE", &:done_ok
      server.on "UID EXPUNGE" do |cmd|
        # Only the moved UIDs are expunged; 3 and 7 remain on the server.
        cmd.untagged "3 EXPUNGE"
        cmd.untagged "3 EXPUNGE"
        cmd.untagged "3 EXPUNGE"
        cmd.done_ok
      end
      copyuid = imap.uid_move_fallback(4..6, "Archive")
      assert_equal({4 => 101, 5 => 102, 6 => 103}, copyuid.uid_mapping)
      copy, store, expunge = 3.times.map { server.commands.pop }
      assert_equal "UID COPY",  copy.name
      assert_equal "UID STORE", store.name
      assert_equal "4:6 +FLAGS (\\Deleted)", store.args
      assert_equal ["UID EXPUNGE", "4:6"], [expunge.name, expunge.args]
      assert server.commands.empty? # no plain EXPUNGE was sent
    end
  end

end
