# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPListTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  test "#list without options keeps its original behavior" do
    with_fake_server do |server, imap|
      server.on "LIST" do |resp|
        resp.untagged %{LIST (\\Noselect) "/" "foo"}
        resp.untagged %{LIST (\\Noinferiors \\Marked) "/" "foo/bar"}
        resp.done_ok
      end
      mailboxes = imap.list("", "foo/%")
      assert_equal %{RUBY0001 LIST "" "foo/%"}, server.commands.pop.raw.strip
      assert_equal 2, mailboxes.size
      assert_equal %i[Noselect],            mailboxes[0].attr
      assert_equal "/",                     mailboxes[0].delim
      assert_equal "foo",                   mailboxes[0].name
      assert_nil                            mailboxes[0].status
      assert_equal %i[Noinferiors Marked],  mailboxes[1].attr
      assert_equal "foo/bar",               mailboxes[1].name
      assert_nil                            mailboxes[1].status
    end
  end

  test "#list sends selection options and return options" do
    with_fake_server do |server, imap|
      server.on "LIST" do |resp|
        resp.untagged %{LIST () "/" "INBOX"}
        resp.done_ok
      end
      imap.list("", "%",
                select_opts: ["SUBSCRIBED"],
                return_opts: ["SUBSCRIBED", ["STATUS", %w[MESSAGES UNSEEN]]])
      assert_equal(
        %{RUBY0001 LIST (SUBSCRIBED) "" "%" RETURN (SUBSCRIBED (STATUS (MESSAGES UNSEEN)))},
        server.commands.pop.raw.strip
      )
    end
  end

  test "#list normalizes symbol options, and STATUS option in flat form" do
    with_fake_server do |server, imap|
      server.on "LIST" do |resp|
        resp.untagged %{LIST () "/" "INBOX"}
        resp.done_ok
      end
      imap.list("", "%",
                select_opts: [:subscribed],
                return_opts: [:status, %i[messages unseen]])
      assert_equal(
        %{RUBY0001 LIST (SUBSCRIBED) "" "%" RETURN (STATUS (MESSAGES UNSEEN))},
        server.commands.pop.raw.strip
      )
    end
  end

  test "#list with STATUS return option correlates by decoded mailbox name" do
    with_fake_server do |server, imap|
      server.on "LIST" do |resp|
        # interleaved, out of order, and not one-to-one with LIST responses
        resp.untagged "STATUS {7}\r\nfoo/bar (MESSAGES 231 UIDNEXT 44292 X-EXT (1 2))"
        resp.untagged %{LIST () "/" {7}\r\nfoo/bar}
        resp.untagged "STATUS INBOX (MESSAGES 1 UNSEEN 2)"
        resp.untagged %{LIST () "/" "inbox"}
        resp.untagged "STATUS other (MESSAGES 9)"
        resp.untagged %{LIST () "/" {7}\r\nfoo/baz}
        resp.untagged "STATUS &AOQ- (UNSEEN 3)"
        resp.untagged %{LIST () "/" "&AOQ-"}
        resp.done_ok
      end
      mailboxes = imap.list("", "*", return_opts: ["STATUS", %w[MESSAGES UNSEEN]])
      assert_equal %{RUBY0001 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))},
                   server.commands.pop.raw.strip
      assert_equal %w[foo/bar inbox foo/baz &AOQ-], mailboxes.map(&:name)

      bar = mailboxes[0]
      assert_equal 231,   bar.status.attr["MESSAGES"]
      # requested but omitted by the server: present and marked missing
      assert              bar.status.attr.key?("UNSEEN")
      assert_nil          bar.status.attr["UNSEEN"]
      assert_equal 44292, bar.status.attr["UIDNEXT"]
      # unknown extension attributes are preserved, not dropped
      assert_equal Net::IMAP::ExtensionData.new([1, 2]), bar.status.attr["X-EXT"]

      # INBOX is case-insensitive: LIST said "inbox", STATUS said "INBOX"
      inbox = mailboxes[1]
      assert_equal 1, inbox.status.attr["MESSAGES"]
      assert_equal 2, inbox.status.attr["UNSEEN"]

      # no STATUS response was returned for foo/baz
      assert_nil mailboxes[2].status

      # modified UTF-7 mailbox names correlate after decoding
      assert_equal 3, mailboxes[3].status.attr["UNSEEN"]
      assert          mailboxes[3].status.attr.key?("MESSAGES")
      assert_nil      mailboxes[3].status.attr["MESSAGES"]

      # STATUS responses for unlisted mailboxes are left in place
      remaining = imap.responses("STATUS")
      assert_equal 1, remaining.size
      assert_equal "other", remaining.first.mailbox
    end
  end

  test "#list without STATUS return option ignores STATUS responses" do
    with_fake_server do |server, imap|
      server.on "LIST" do |resp|
        resp.untagged %{LIST () "/" "INBOX"}
        resp.done_ok
      end
      mailboxes = imap.list("", "*", return_opts: ["SUBSCRIBED"])
      assert_equal %{RUBY0001 LIST "" "*" RETURN (SUBSCRIBED)},
                   server.commands.pop.raw.strip
      assert_equal 1, mailboxes.size
      assert_nil mailboxes.first.status
    end
  end

end
