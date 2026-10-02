require_relative "../spec_helper"
require "roda/plugins/flash_notifications"

describe "flash_notifications plugin" do
  include CookieJar

  it "supports rereading, acknowledging, duplicate acks, expiration, and capacity eviction across requests" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :flash_notifications, :retention_period=>60, :max_notifications=>2

      route do |r|
        r.post "notify" do
          flash_notify(r.params["message"])
        end

        r.post "ack" do
          ack_flash_notification(r.params["id"]).to_s
        end

        ["page", "poll"].each do |path|
          r.get path do
            flash_notifications.map { |notification| notification["message"] }.join(",")
          end
        end
      end
    end

    first_id = nil

    Time.stub(:now, Time.at(10)) do
      first_id = body("/notify", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"message=first")
    end

    Time.stub(:now, Time.at(20)) { body("/page").must_equal "first" }
    Time.stub(:now, Time.at(30)) { body("/poll").must_equal "first" }

    Time.stub(:now, Time.at(40)) do
      body("/ack", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"id=#{first_id}").must_equal "true"
      body("/page").must_equal ""
      body("/ack", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"id=#{first_id}").must_equal "false"
    end

    Time.stub(:now, Time.at(50)) do
      body("/notify", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"message=second")
      body("/ack", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"id=#{first_id}").must_equal "false"
      body("/poll").must_equal "second"

      body("/notify", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"message=third")
      body("/notify", "REQUEST_METHOD"=>"POST", "QUERY_STRING"=>"message=fourth")
      body("/page").must_equal "third,fourth"
    end

    Time.stub(:now, Time.at(112)) { body("/poll").must_equal "" }
  end

  it "keeps regular flash entries separate from acknowledged notifications" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :flash_notifications

      route do |r|
        r.post "notify" do
          flash_notify("notification")
        end

        r.get "set-flash" do
          flash["a"] = "flash"
          "set"
        end

        r.get "page" do
          messages = flash_notifications.map { |notification| notification["message"] }
          "#{flash['a']}:#{messages.join(',')}"
        end
      end
    end

    body("/notify", "REQUEST_METHOD"=>"POST")
    body("/set-flash")
    body("/page").must_equal "flash:notification"
    body("/page").must_equal ":notification"
  end
end

describe Roda::RodaPlugins::FlashNotifications::FlashNotificationStore do
  def store(session={}, now=0, retention_period: 60, max_notifications: 20)
    Roda::RodaPlugins::FlashNotifications::FlashNotificationStore.new(
      session,
      "_flash_notifications",
      now,
      retention_period,
      max_notifications
    )
  end

  it "returns notifications repeatedly and acknowledges only the matching ID" do
    session = {}
    first_store = store(session)
    first_id = first_store.add("first")
    second_id = store(session, 1).add("second")
    first_store.persist

    second_store = store(session, 2)
    second_store.notifications.map { |notification| notification["message"] }.must_equal ["first", "second"]
    second_store.notifications.map { |notification| notification["message"] }.must_equal ["first", "second"]
    second_store.acknowledge(first_id).must_equal true
    second_store.acknowledge(first_id).must_equal false
    second_store.acknowledge(first_id).must_equal false
    second_store.notifications.map { |notification| notification["id"] }.must_equal [second_id]
    second_store.persist

    store(session, 3).notifications.map { |notification| notification["message"] }.must_equal ["second"]
  end

  it "does not let a stale acknowledgement remove a later notification" do
    notification_store = store
    old_id = notification_store.add("old")
    notification_store.acknowledge(old_id).must_equal true
    notification_store.add("new")

    notification_store.acknowledge(old_id).must_equal false
    notification_store.notifications.map { |notification| notification["message"] }.must_equal ["new"]
  end

  it "expires notifications after the retention period" do
    session = {}
    store(session, 0).add("first")

    store(session, 59).notifications.map { |notification| notification["message"] }.must_equal ["first"]
    notification_store = store(session, 60)
    notification_store.notifications.must_equal []
    notification_store.persist
    session.must_equal({})
  end

  it "evicts the oldest notifications beyond capacity" do
    session = {}
    notification_store = store(session, 0, :max_notifications=>2)
    notification_store.add("first")
    notification_store.add("second")
    notification_store.add("third")
    notification_store.persist

    session["_flash_notifications"].map { |notification| notification["message"] }.must_equal ["second", "third"]
    store(session, 1, :max_notifications=>1).notifications.map { |notification| notification["message"] }.must_equal ["third"]
  end

  it "removes malformed stored notifications" do
    session = {"_flash_notifications"=>["bad", {"id"=>"good", "expires_at"=>60, "message"=>"good"}]}

    store(session, 0).notifications.must_equal [{"id"=>"good", "message"=>"good", "expires_at"=>60}]
  end
end
