# frozen_string_literal: true

require "net/imap"
require "test/unit"
require_relative "fake_server"

class IMAPListTest < Net::IMAP::TestCase
  include Net::IMAP::FakeServer::TestHelper

  test("basic list remains an array") do
    with_fake_server do |server, imap|
      server.on "LIST" do |cmd|
        cmd.untagged "LIST", "() \"/\" {3}\r\nfoo"
        cmd.done_ok
      end

      result = imap.list("", "foo")

      assert_instance_of Array, result
      assert_instance_of Net::IMAP::MailboxList, result.first
      assert_equal "foo", result.first.name
      assert_equal 'LIST "" foo', server.commands.pop.raw.strip
    end
  end

  test("extended selection options and return options") do
    with_fake_server do |server, imap|
      server.on "LIST" do |cmd|
        cmd.untagged "LIST", "(\\Subscribed) \"/\" {3}\r\nfoo"
        cmd.untagged "LIST", "() \"/\" {3}\r\nbar"
        cmd.untagged "STATUS", "{3}\r\nbar (MESSAGES 5 X-FOO 12)"
        cmd.untagged "STATUS", "{3}\r\nfoo (UNSEEN 2 X-FOO (a b))"
        cmd.done_ok
      end

      result = imap.list(
        "", "*",
        [:SUBSCRIBED],
        return: [{status: ["MESSAGES", :UNSEEN, :deleted]}, :SPECIAL_USE]
      )

      assert_instance_of Net::IMAP::MailboxListResult, result
      assert_equal ["foo", "bar"], result.map(&:name)
      assert_equal(
        {
          "MESSAGES" => nil,
          "UNSEEN"   => 2,
          "DELETED"  => nil,
          "X-FOO"    => Net::IMAP::ExtensionData.new(%w[a b]),
        },
        result.status["foo"]
      )
      assert_equal(
        {
          "MESSAGES" => 5,
          "UNSEEN"   => nil,
          "DELETED"  => nil,
          "X-FOO"    => 12,
        },
        result.status["bar"]
      )
      assert_equal "foo", result.first.name
      assert_equal "bar", result[1].name
      assert_empty imap.responses("LIST")
      assert_empty imap.responses("STATUS")
      assert_equal(
        'LIST "" "*" (SUBSCRIBED) RETURN (STATUS (MESSAGES UNSEEN DELETED) SPECIAL_USE)',
        server.commands.pop.raw.strip
      )
    end
  end

  test("return options without STATUS still return a structured result") do
    with_fake_server do |server, imap|
      server.on "LIST" do |cmd|
        cmd.untagged "LIST", "(\\Subscribed) \"/\" foo (SUBSCRIBED NIL X-UNKNOWN 42)"
        cmd.done_ok
      end

      result = imap.list("", "*", return: [:SUBSCRIBED])

      assert_instance_of Net::IMAP::MailboxListResult, result
      assert_equal({}, result.status)
      assert_equal 42, result.first.extended["X-UNKNOWN"]
      assert_equal 'LIST "" "*" RETURN (SUBSCRIBED)', server.commands.pop.raw.strip
    end
  end

  test("STATUS is matched by decoded mailbox identity") do
    with_fake_server do |server, imap|
      server.on "LIST" do |cmd|
        cmd.untagged "LIST", "() \"/\" {5}\r\ninbox"
        cmd.untagged "STATUS", "{3}\r\nFoo (MESSAGES 1)"
        cmd.untagged "STATUS", "{5}\r\nINBOX (MESSAGES 2)"
        cmd.done_ok
      end

      result = imap.list("", "*", return: {status: [:messages]})

      assert_equal ["inbox"], result.map(&:name)
      assert_equal({"MESSAGES" => 2}, result.status["inbox"])
      refute_includes result.status, "Foo"
    end
  end
end
