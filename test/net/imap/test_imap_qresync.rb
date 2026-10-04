# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPQResyncTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  QRESYNC_SERVER = {
    with_extensions:         %i[ENABLE CONDSTORE QRESYNC],
    capabilities_enablable:  %w[CONDSTORE QRESYNC],
  }.freeze

  NO_QRESYNC_SERVER = {
    with_extensions:         %i[ENABLE CONDSTORE],
    capabilities_enablable:  %w[CONDSTORE],
  }.freeze

  STORED = {
    uidvalidity:    3857529045,
    highest_modseq: 982,
    known_uids:     "1:100,200",
  }.freeze

  def on_qresync_select(server, uidvalidity: 3857529045, highestmodseq: 989)
    server.on "SELECT", "EXAMINE" do |resp|
      resp.untagged "OK [UIDVALIDITY #{uidvalidity}] UIDs valid"
      resp.untagged "OK [HIGHESTMODSEQ #{highestmodseq}] Highest mod-seq"
      resp.untagged "VANISHED (EARLIER) 3:5,9"
      resp.untagged "VANISHED 77"
      resp.untagged "172 EXISTS"
      resp.untagged "1 RECENT"
      resp.done_ok code: "READ-WRITE"
    end
  end

  test "#select with qresync enables QRESYNC and sends select params" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      on_qresync_select(server)
      result = imap.select("INBOX", qresync: STORED)
      assert_equal "RUBY0001 ENABLE QRESYNC",
                   server.commands.pop.raw.strip
      assert_equal "RUBY0002 SELECT INBOX (QRESYNC (3857529045 982 1:100,200))",
                   server.commands.pop.raw.strip
      assert_empty server.commands
      assert_kind_of Net::IMAP::QResyncResult, result
      assert result.qresync?
      assert_equal "INBOX",     result.mailbox
      assert_equal 3857529045,  result.uidvalidity
      assert_equal 989,         result.highest_modseq
      refute result.nomodseq?
    end
  end

  test "#examine with qresync sends select params" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      on_qresync_select(server)
      result = imap.examine("INBOX", qresync: STORED)
      server.commands.pop # ENABLE
      assert_equal "RUBY0002 EXAMINE INBOX (QRESYNC (3857529045 982 1:100,200))",
                   server.commands.pop.raw.strip
      assert result.qresync?
    end
  end

  test "qresync result separates VANISHED (EARLIER) from online deletions" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      on_qresync_select(server)
      result = imap.select("INBOX", qresync: STORED)
      assert_equal Net::IMAP::SequenceSet["3:5,9"], result.vanished_earlier
      assert_equal Net::IMAP::SequenceSet["77"],    result.vanished
      assert_empty result.expunged
    end
  end

  test "qresync known_uids is omitted when nil or empty" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      on_qresync_select(server)
      imap.select("INBOX", qresync: STORED.merge(known_uids: nil))
      server.commands.pop # ENABLE
      assert_equal "RUBY0002 SELECT INBOX (QRESYNC (3857529045 982))",
                   server.commands.pop.raw.strip
      imap.select("INBOX", qresync: STORED.merge(known_uids: []))
      assert_equal "RUBY0003 SELECT INBOX (QRESYNC (3857529045 982))",
                   server.commands.pop.raw.strip
    end
  end

  test "qresync does not re-enable when QRESYNC is already enabled" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      on_qresync_select(server)
      imap.enable "QRESYNC"
      assert_equal "RUBY0001 ENABLE QRESYNC", server.commands.pop.raw.strip
      imap.select("INBOX", qresync: STORED)
      assert_equal "RUBY0002 SELECT INBOX (QRESYNC (3857529045 982 1:100,200))",
                   server.commands.pop.raw.strip
      assert_empty server.commands
    end
  end

  test "UIDVALIDITY mismatch raises and requires a rebuild" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      on_qresync_select(server, uidvalidity: 999999)
      error = assert_raise(Net::IMAP::UIDValidityMismatchError) do
        imap.select("INBOX", qresync: STORED)
      end
      assert_equal "INBOX",    error.mailbox
      assert_equal 3857529045, error.expected
      assert_equal 999999,     error.actual
      assert_match(/rebuilt/, error.message)
    end
  end

  test "unsupported server raises CapabilityError by default" do
    with_fake_server(**NO_QRESYNC_SERVER) do |server, imap|
      error = assert_raise(Net::IMAP::CapabilityError) do
        imap.select("INBOX", qresync: STORED)
      end
      assert_match(/QRESYNC/, error.message)
      assert_empty server.commands
    end
  end

  test "unsupported server degrades to plain select when chosen" do
    with_fake_server(**NO_QRESYNC_SERVER) do |server, imap|
      result = imap.select("INBOX", qresync: STORED, on_unsupported: :degrade)
      assert_equal "RUBY0001 SELECT INBOX", server.commands.pop.raw.strip
      refute result.qresync?
      assert_equal 3857529045, result.uidvalidity
      assert result.nomodseq?
      assert_empty result.vanished_earlier
    end
  end

  test "invalid on_unsupported raises ArgumentError" do
    with_fake_server(**NO_QRESYNC_SERVER) do |server, imap|
      assert_raise(ArgumentError) do
        imap.select("INBOX", qresync: STORED, on_unsupported: :bogus)
      end
    end
  end

  test "refused ENABLE QRESYNC raises or degrades" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      server.on("ENABLE") { |resp| resp.fail_no "cannot enable" }
      error = assert_raise(Net::IMAP::CapabilityError) do
        imap.select("INBOX", qresync: STORED)
      end
      assert_match(/refused/, error.message)
      server.commands.pop # failed ENABLE
      result = imap.select("INBOX", qresync: STORED, on_unsupported: :degrade)
      server.commands.pop # failed ENABLE
      assert_equal "RUBY0003 SELECT INBOX", server.commands.pop.raw.strip
      refute result.qresync?
    end
  end

  test "unconfirmed ENABLE QRESYNC raises CapabilityError" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      server.on("ENABLE") { |resp| resp.done_ok } # no ENABLED response
      error = assert_raise(Net::IMAP::CapabilityError) do
        imap.select("INBOX", qresync: STORED)
      end
      assert_match(/did not confirm/, error.message)
    end
  end

  test "degraded select still enforces UIDVALIDITY match" do
    with_fake_server(**NO_QRESYNC_SERVER) do |server, imap|
      assert_raise(Net::IMAP::UIDValidityMismatchError) do
        imap.select("INBOX", on_unsupported: :degrade,
                    qresync: STORED.merge(uidvalidity: 12345))
      end
    end
  end

  test "degraded select collects EXPUNGE as online deletions" do
    with_fake_server(**NO_QRESYNC_SERVER) do |server, imap|
      server.on "SELECT" do |resp|
        resp.untagged "OK [UIDVALIDITY 3857529045] UIDs valid"
        resp.untagged "2 EXPUNGE"
        resp.untagged "171 EXISTS"
        resp.done_ok code: "READ-WRITE"
      end
      result = imap.select("INBOX", qresync: STORED, on_unsupported: :degrade)
      refute result.qresync?
      assert_equal [2], result.expunged
      assert_empty result.vanished
      assert_empty result.vanished_earlier
    end
  end

  test "qresync requires stored uidvalidity and highest_modseq" do
    with_fake_server(**QRESYNC_SERVER) do |server, imap|
      assert_raise(ArgumentError) do
        imap.select("INBOX", qresync: {highest_modseq: 982})
      end
      assert_raise(ArgumentError) do
        imap.select("INBOX", qresync: {uidvalidity: 3857529045})
      end
      assert_raise(ArgumentError) do
        imap.select("INBOX", qresync: STORED.merge(uidvalidity: "not a number"))
      end
    end
  end

  test "#select without qresync still returns the tagged response" do
    with_fake_server do |server, imap|
      response = imap.select("INBOX")
      assert_kind_of Net::IMAP::TaggedResponse, response
      assert_equal "RUBY0001 SELECT INBOX", server.commands.pop.raw.strip
    end
  end

end
