# frozen_string_literal: true

require "net/imap"
require "test/unit"

class IMAPListArgsTest < Net::IMAP::TestCase
  def imap
    @imap ||= begin
      imap = Net::IMAP.allocate
      imap.send(:mon_initialize)
      imap.instance_variable_set(:@config, Net::IMAP.config.new)
      imap.instance_variable_set(:@responses, {"LIST" => [], "STATUS" => []})
      def imap.send_command(*); end
      imap
    end
  end

  test "public list accepts the return keyword and returns a structured result" do
    client = Net::IMAP.allocate
    client.send(:mon_initialize)
    client.instance_variable_set(:@config, Net::IMAP.config.new)
    client.instance_variable_set(:@responses, {"LIST" => [], "STATUS" => []})
    def client.send_command(*); end

    result = client.list("", "*", :SUBSCRIBED, return: {children: nil})

    assert_instance_of Net::IMAP::MailboxListResult, result
  end

  def seed_response(type, data)
    imap.instance_variable_get(:@responses)[type] << data
  end

  def mailbox(name)
    Net::IMAP::MailboxList.new([], "/", name)
  end

  def status(name, attrs)
    Net::IMAP::StatusData.new(name, attrs)
  end

  test "normalizes extended selection and return options" do
    args, attrs = imap.send(
      :list_args,
      "", "*",
      [[[:REMOTE, [:SPECIAL_USE]], :SUBSCRIBED]],
      [{status: [:messages, "UNSEEN"]}, "CHILDREN"],
      true
    )

    assert_equal(
      ["", "*", [["REMOTE", ["SPECIAL_USE"]], "SUBSCRIBED"],
       "RETURN", [["STATUS", ["MESSAGES", "UNSEEN"]], "CHILDREN"]],
      args
    )
    assert_equal ["MESSAGES", "UNSEEN"], attrs
  end

  test "sends an empty explicit selection option list" do
    args, attrs = imap.send(
      :list_args, "", "*", [[]], nil, true
    )

    assert_equal ["", "*", []], args
    assert_equal [], attrs
  end

  test "STATUS return options require an array of attributes" do
    assert_raise(TypeError) do
      imap.send(:normalize_list_return_options, [["STATUS", :MESSAGES]])
    end
  end

  test "old list arguments do not include selection options" do
    args, attrs = imap.send(:list_args, "", "foo", ["not-an-option"], nil, false)

    assert_equal ["", "foo"], args
    assert_equal [], attrs
  end

  test "supports array and mailbox-name access" do
    result = Net::IMAP::MailboxListResult.new(
      mailboxes: [mailbox("foo")],
      status: {"foo" => {"MESSAGES" => 1}}
    )

    assert_equal "foo", result.first.name
    assert_equal({"MESSAGES" => 1}, result["foo"])
    assert_equal [mailbox("foo")], Array(result)
  end

  test "associates STATUS data by mailbox name and marks missing values" do
    [mailbox("foo"), mailbox("bar")].each { seed_response("LIST", _1) }
    [
      status("bar", {"MESSAGES" => 5, "X-EXTRA" => true}),
      status("other", {"MESSAGES" => 99}),
      status("foo", {"UNSEEN" => 2}),
      status("queued", {"MESSAGES" => 42})
    ].each { seed_response("STATUS", _1) }

    result = imap.send(
      :list_extended_result,
      ["", "*"],
      ["MESSAGES", "UNSEEN", "DELETED"]
    )

    assert_equal ["foo", "bar"], result.map(&:name)
    assert_equal(
      {
        "foo" => {
          "MESSAGES" => nil,
          "UNSEEN"   => 2,
          "DELETED"  => nil,
        },
        "bar" => {
          "MESSAGES" => 5,
          "UNSEEN"   => nil,
          "DELETED"  => nil,
          "X-EXTRA"  => true,
        },
      },
      result.status
    )
    assert_empty imap.responses["LIST"]
    assert_equal(
      [
        status("other", {"MESSAGES" => 99}),
        status("queued", {"MESSAGES" => 42}),
      ],
      imap.responses("STATUS")
    )
  end

  test "INBOX STATUS is case-insensitive" do
    seed_response("LIST", mailbox("iNbOx"))
    seed_response("STATUS", status("INBOX", {"MESSAGES" => 1}))

    result = imap.send(:list_extended_result, ["", "*"], ["MESSAGES"])

    assert_equal({"iNbOx" => {"MESSAGES" => 1}}, result.status)
  end
end
