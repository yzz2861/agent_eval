# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPUIDMoveFallbackTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  UIDS = [3955, 3960..3962].freeze

  def with_uidplus_no_move(select: "INBOX", **opts, &block)
    with_fake_server(select: select,
                     extensions: %i[UIDPLUS],
                     **opts, &block)
  end

  def drain_select_command!(server)
    cmd = server.commands.pop
    assert_equal "SELECT", cmd.name
  end

  # Full happy path: COPY, then flag, then a *targeted* UID EXPUNGE.
  test "fallback copies, flags, and uid-expunges" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 3955,3960:3962 3963:3966"
      end
      server.on "UID STORE" do |cmd|
        cmd.untagged("3 FETCH (UID 3960 FLAGS (\\Seen \\Deleted))")
        cmd.done_ok
      end
      server.on "UID EXPUNGE" do |cmd|
        cmd.untagged("3 EXPUNGE")
        cmd.untagged("3 EXPUNGE")
        cmd.untagged("3 EXPUNGE")
        cmd.untagged("3 EXPUNGE")
        cmd.done_ok
      end

      result = imap.uid_move_fallback(UIDS, "trash")

      copy, store, expunge = 3.times.map { server.commands.pop }
      assert_equal ["UID COPY",    "3955,3960:3962 trash"],
                   [copy.name, copy.args]
      assert_equal ["UID STORE",   "3955,3960:3962 +FLAGS (\\Deleted)"],
                   [store.name, store.args]
      assert_equal ["UID EXPUNGE", "3955,3960:3962"],
                   [expunge.name, expunge.args]
      assert_empty server.commands

      assert_predicate result, :completed?
      assert_equal %i[copy store expunge], result.stages
      assert_equal 3857529045, result.uidvalidity
      assert_kind_of Net::IMAP::CopyUIDData, result.copy_uid
      assert_equal(
        {3955 => 3963, 3960 => 3964, 3961 => 3965, 3962 => 3966},
        result.uid_mapping,
      )
      assert_kind_of Array, result.store
      assert_equal [3, 3, 3, 3], result.expunged
    end
  end

  # Acceptance scenario: the mailbox already contains *other* \Deleted
  # messages.  The fallback must only UID EXPUNGE the moved UIDs and must
  # never send an untargeted EXPUNGE that would remove the other messages.
  test "pre-existing deleted messages are not expunged" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server

      server.on "UID COPY" do |cmd|
        # An unrelated message was already flagged \Deleted before the move.
        cmd.done_ok code: "COPYUID 38505 3955,3960:3962 3963:3966"
      end
      server.on "UID STORE", &:done_ok
      untargeted_expunge = false
      server.on "EXPUNGE" do |cmd|
        untargeted_expunge = true
        cmd.fail_bad "untargeted EXPUNGE must never be sent"
      end
      expunge_args = nil
      server.on "UID EXPUNGE" do |cmd|
        expunge_args = cmd.args
        # Only the moved messages are removed.
        cmd.untagged("3 EXPUNGE")
        cmd.untagged("3 EXPUNGE")
        cmd.untagged("3 EXPUNGE")
        cmd.untagged("3 EXPUNGE")
        cmd.done_ok
      end

      result = imap.uid_move_fallback(UIDS, "trash")

      assert_equal "3955,3960:3962", expunge_args
      refute untargeted_expunge, "an untargeted EXPUNGE was sent"
      assert_predicate result, :expunged?
      assert_equal [3, 3, 3, 3], result.expunged
    end
  end

  test "COPY success then STORE failure reports stages and uid mapping" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 3955,3960:3962 3963:3966"
      end
      server.on "UID STORE" do |cmd|
        cmd.fail_no "server is temporarily unable to store flags"
      end
      server.on "UID EXPUNGE" do |cmd|
        flunk "UID EXPUNGE must not be sent after STORE failure"
        cmd.done_ok
      end

      error = assert_raise(Net::IMAP::FallbackMoveIncomplete) do
        imap.uid_move_fallback(UIDS, "trash")
      end

      result = error.result
      assert_equal %i[copy], result.stages
      assert_predicate result, :copied?
      refute_predicate result, :flagged?
      refute_predicate result, :expunged?
      refute_predicate result, :completed?
      assert_kind_of Net::IMAP::CopyUIDData, result.copy_uid
      assert_equal(
        {3955 => 3963, 3960 => 3964, 3961 => 3965, 3962 => 3966},
        result.uid_mapping,
      )

      copy = server.commands.pop
      assert_equal "UID COPY", copy.name
      store = server.commands.pop
      assert_equal "UID STORE", store.name
      assert_empty server.commands
    end
  end

  test "STORE success then UID EXPUNGE failure stops at expunge stage" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 3955 3967"
      end
      server.on "UID STORE", &:done_ok
      server.on "UID EXPUNGE" do |cmd|
        cmd.fail_no "expunge unavailable"
      end

      error = assert_raise(Net::IMAP::FallbackMoveIncomplete) do
        imap.uid_move_fallback(3955, "trash")
      end

      assert_equal %i[copy store], error.result.stages
      assert_predicate error.result, :flagged?
      refute_predicate error.result, :expunged?
      assert_kind_of Net::IMAP::CopyUIDData, error.result.copy_uid
      assert_equal({3955 => 3967}, error.result.uid_mapping)
      assert_nil error.result.expunged
    end
  end

  test "stops when UIDVALIDITY changes during the fallback" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server
      server.on "UID COPY" do |cmd|
        # A different server/session invalidated UIDs mid-fallback.
        cmd.untagged("OK [UIDVALIDITY 4242] UIDVALIDITY changed")
        cmd.done_ok code: "COPYUID 38505 3955 3967"
      end
      server.on "UID STORE" do |cmd|
        flunk "STORE must not be sent after UIDVALIDITY changed"
        cmd.done_ok
      end
      server.on "UID EXPUNGE" do |cmd|
        flunk "UID EXPUNGE must not be sent after UIDVALIDITY changed"
        cmd.done_ok
      end

      error = assert_raise(Net::IMAP::FallbackMailboxChanged) do
        imap.uid_move_fallback(3955, "trash")
      end
      assert_equal %i[copy], error.result.stages
      assert_equal 3857529045, error.result.uidvalidity
      assert_equal "UID COPY", server.commands.pop.name
      assert_empty server.commands
    end
  end

  test "stops when the mailbox is unselected during the fallback" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server
      server.on "UID COPY" do |cmd|
        cmd.untagged("OK [CLOSED] another client deleted the mailbox")
        cmd.done_ok code: "COPYUID 38505 3955 3967"
      end
      server.on "UID STORE" do |cmd|
        flunk "STORE must not be sent once unselected"
        cmd.done_ok
      end
      server.on "UID EXPUNGE" do |cmd|
        flunk "UID EXPUNGE must not be sent once unselected"
        cmd.done_ok
      end

      error = assert_raise(Net::IMAP::FallbackMailboxChanged) do
        imap.uid_move_fallback(3955, "trash")
      end
      assert_equal %i[copy], error.result.stages
    end
  end

  test "refuses to fallback without UIDPLUS or IMAP4rev2" do
    with_fake_server(select: "INBOX",
                     without_extensions: %i[MOVE UIDPLUS]) do |server, imap|
      drain_select_command! server
      sent_expunge = false
      server.on "EXPUNGE" do |cmd|
        sent_expunge = true
        cmd.done_ok
      end

      assert_raise_with_message(ArgumentError, /UIDPLUS|IMAP4rev2/) do
        imap.uid_move_fallback(3955, "trash")
      end
      refute sent_expunge
      assert_empty server.commands
    end
  end

  test "uses atomic UID MOVE when MOVE is advertised" do
    with_fake_server(select: "INBOX",
                     extensions: %i[MOVE UIDPLUS]) do |server, imap|
      drain_select_command! server
      server.on "UID MOVE" do |cmd|
        cmd.untagged("OK [COPYUID 38505 3955 3967] Moved")
        cmd.done_ok
      end
      %w[UID COPY UID STORE UID EXPUNGE EXPUNGE].each do |name|
        server.on(name) { |cmd| cmd.fail_bad "#{name} should not be sent" }
      end

      result = imap.uid_move_fallback(3955, "trash")

      assert_equal %i[move], result.stages
      assert_predicate result, :completed?
      assert_kind_of Net::IMAP::CopyUIDData, result.copy_uid
      assert_equal({3955 => 3967}, result.uid_mapping)
      assert_equal "UID MOVE", server.commands.pop.name
      assert_empty server.commands
    end
  end

  test "use_move: false forces the fallback even when MOVE is available" do
    with_fake_server(select: "INBOX",
                     extensions: %i[MOVE UIDPLUS]) do |server, imap|
      drain_select_command! server
      server.on "UID COPY" do |cmd|
        cmd.done_ok code: "COPYUID 38505 3955 3967"
      end
      server.on "UID STORE", &:done_ok
      server.on "UID EXPUNGE", &:done_ok
      server.on "UID MOVE" do |cmd|
        flunk "UID MOVE must not be used with use_move: false"
        cmd.done_ok
      end

      result = imap.uid_move_fallback(3955, "trash", use_move: false)
      assert_equal %i[copy store expunge], result.stages
      assert_equal ["UID COPY", "UID STORE", "UID EXPUNGE"],
                   3.times.map { server.commands.pop.name }
    end
  end

  test "use_move: true raises when MOVE is not advertised" do
    with_uidplus_no_move do |server, imap|
      drain_select_command! server
      assert_raise_with_message(ArgumentError, /MOVE capability/) do
        imap.uid_move_fallback(3955, "trash", use_move: true)
      end
      assert_empty server.commands
    end
  end

  test "raises FallbackMailboxChanged when no mailbox is selected" do
    with_fake_server(extensions: %i[UIDPLUS]) do |server, imap|
      assert_raise(Net::IMAP::FallbackMailboxChanged) do
        imap.uid_move_fallback(3955, "trash")
      end
      assert_empty server.commands
    end
  end

end
