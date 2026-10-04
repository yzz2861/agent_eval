# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPSelectTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  RESYNC_MAILBOX = {
    name: "INBOX",
    exists: 6,
    recent: 0,
    unseen: 4,
    uidvalidity: 3857529045,
    uidnext: 10,
    highestmodseq: 123460,
    vanished_earlier: "1:2,5",
    vanished: "3",
    fetch_changes: [
      "* 4 FETCH (UID 4 MODSEQ (123457) FLAGS (\\Seen))",
      "* 5 FETCH (UID 6 MODSEQ (123460) FLAGS (\\Flagged))",
    ],
  }.freeze

  test "#select with condstore" do
    with_fake_server do |server, imap|
      imap.select "inbox", condstore: true
      assert_equal("RUBY0001 SELECT inbox (CONDSTORE)",
                   server.commands.pop.raw.strip)
    end
  end

  test "#examine with condstore" do
    with_fake_server do |server, imap|
      imap.examine "inbox", condstore: true
      assert_equal("RUBY0001 EXAMINE inbox (CONDSTORE)",
                   server.commands.pop.raw.strip)
    end
  end

  test "#select with qresync returns separated historical and current removals" do
    with_qresync_server(mailboxes: {"INBOX" => RESYNC_MAILBOX.dup}) do |server, imap|
      result = imap.select("inbox", qresync: [3857529045, 123456, "1:6"])

      commands = 2.times.map { server.commands.pop.raw.strip }
      assert_include commands, "RUBY0001 ENABLE QRESYNC"
      assert_include(
        commands,
        "RUBY0002 SELECT inbox (QRESYNC (3857529045 123456 1:6))"
      )

      assert_instance_of Net::IMAP::QResyncResult, result
      assert_equal 3857529045, result.uidvalidity
      assert_equal 123460, result.highestmodseq
      assert_equal [1, 2, 5], result.vanished_earlier.to_a
      assert result.vanished_earlier.earlier?
      assert_equal [3], result.vanished.to_a
      refute result.vanished.earlier?
      assert_equal [4, 6], result.fetches.map(&:uid)
      refute_predicate result, :degraded?
      refute_predicate result, :read_only?
    end
  end

  test "#examine with qresync uses qresync params and is read-only" do
    with_qresync_server(mailboxes: {"INBOX" => RESYNC_MAILBOX.dup}) do |server, imap|
      result = imap.examine("inbox", qresync: {
        uidvalidity: 3857529045,
        highestmodseq: 123456,
        known_uids: 1..6,
      })

      server.commands.pop # ENABLE
      assert_equal(
        "RUBY0002 EXAMINE inbox (QRESYNC (3857529045 123456 1:6))",
        server.commands.pop.raw.strip
      )
      assert_predicate result, :read_only?
    end
  end

  test "qresync omits the known uid set when it is not supplied" do
    with_qresync_server(mailboxes: {"INBOX" => RESYNC_MAILBOX.dup}) do |server, imap|
      imap.select "inbox", qresync: [3857529045, 123456]
      server.commands.pop # ENABLE
      assert_equal(
        "RUBY0002 SELECT inbox (QRESYNC (3857529045 123456))",
        server.commands.pop.raw.strip
      )
    end
  end

  test "qresync is rejected by default when the server does not support it" do
    with_fake_server(without_extensions: %i[CONDSTORE QRESYNC],
                     capabilities_enablable: %w[UTF8=ACCEPT]) do |server, imap|
      assert_raise Net::IMAP::QResyncNotSupportedError do
        imap.select "inbox", qresync: [3857529045, 123456, "1:6"]
      end
      assert_equal 0, server.commands.size
    end
  end

  test "qresync falls back to a plain select when required is false" do
    with_fake_server(without_extensions: %i[CONDSTORE QRESYNC],
                     capabilities_enablable: %w[UTF8=ACCEPT]) do |server, imap|
      result = imap.select(
        "inbox", qresync: [3857529045, 123456, "1:6"], qresync_required: false
      )

      assert_predicate result, :degraded?
      assert_empty result.vanished_earlier.to_a
      assert_empty result.vanished.to_a
      assert_nil result.highestmodseq
      assert imap.selected?
      assert_equal "RUBY0001 SELECT inbox", server.commands.pop.raw.strip
    end
  end

  test "a fallback selection still rebuilds when UIDVALIDITY changes" do
    mailbox = RESYNC_MAILBOX.dup.merge(uidvalidity: 999)
    with_fake_server(
      without_extensions: %i[CONDSTORE QRESYNC],
      capabilities_enablable: %w[UTF8=ACCEPT],
      mailboxes: {"INBOX" => mailbox}
    ) do |server, imap|
      error = assert_raise Net::IMAP::UIDValidityError do
        imap.select(
          "inbox", qresync: [3857529045, 123456, "1:6"], qresync_required: false
        )
      end
      assert_predicate error.result, :degraded?
      assert_equal "RUBY0001 SELECT inbox", server.commands.pop.raw.strip
    end
  end

  test "qresync falls back when capability negotiation fails" do
    with_fake_server(with_extensions: %i[CONDSTORE QRESYNC],
                     capabilities_enablable: %w[CONDSTORE QRESYNC]) do |server, imap|
      server.on "ENABLE" do |resp|
        resp.fail_no "QRESYNC unavailable"
      end
      result = imap.select(
        "inbox", qresync: [3857529045, 123456, "1:6"], qresync_required: false
      )
      assert_predicate result, :degraded?
      assert_equal "RUBY0001 ENABLE QRESYNC",
                   server.commands.pop.raw.strip
      assert_equal "RUBY0002 SELECT inbox", server.commands.pop.raw.strip
    end
  end

  test "qresync raises UIDValidityError and does not mix old and new UIDs" do
    mailbox = RESYNC_MAILBOX.dup.merge(uidvalidity: 999, highestmodseq: 2)
    with_qresync_server(mailboxes: {"INBOX" => mailbox}) do |server, imap|
      error = assert_raise Net::IMAP::UIDValidityError do
        imap.select "inbox", qresync: [3857529045, 1, "1:6"]
      end

      assert_equal 3857529045, error.expected_uidvalidity
      assert_equal 999, error.uidvalidity
      refute_predicate error.result, :degraded?
      assert_equal 999, error.result.uidvalidity
      assert_empty imap.responses("VANISHED")
      assert_empty imap.responses("FETCH")
      assert imap.selected?
      assert_equal "RUBY0001 ENABLE QRESYNC",
                   server.commands.pop.raw.strip
      assert_equal "RUBY0002 SELECT inbox (QRESYNC (3857529045 1 1:6))",
                   server.commands.pop.raw.strip
    end
  end

  private

  def with_qresync_server(**opts, &block)
    with_fake_server(
      **opts,
      with_extensions: %i[CONDSTORE QRESYNC],
      capabilities_enablable: %w[CONDSTORE QRESYNC],
      &block
    )
  end

end
