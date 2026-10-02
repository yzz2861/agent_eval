require_relative "../spec_helper"
require "json"
require "roda/plugins/flash_notifications"

describe "flash_notifications plugin" do
  include CookieJar

  it "supports rereading, expiration, acknowledgment, and capacity eviction in order" do
    current_time = 0

    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :flash_notifications, :retention=>10, :capacity=>3, :clock=>lambda{current_time}

      route do |r|
        r.get "page" do
          flash_notifications.to_json
        end

        r.get "poll" do
          flash_notifications.to_json
        end

        r.post "notifications" do
          id = add_flash_notification(r.params["message"])
          {"id"=>id}.to_json
        end

        r.post "notifications", String do |id|
          {"acknowledged"=>ack_flash_notification(id)}.to_json
        end
      end
    end

    body("/page").must_equal "[]"
    header(RodaResponseHeaders::SET_COOKIE, "/poll").must_be_nil

    body("/notifications", "REQUEST_METHOD"=>"POST", "rack.input"=>rack_input("message=one")).must_equal '{"id":1}'

    page_notifications = JSON.parse(body("/page"))
    poll_notifications = JSON.parse(body("/poll"))
    page_notifications.must_equal [{"id"=>1, "message"=>"one", "expires_at"=>10}]
    poll_notifications.must_equal page_notifications

    current_time = 10
    body("/page").must_equal "[]"
    body("/poll").must_equal "[]"

    body("/notifications", "REQUEST_METHOD"=>"POST", "rack.input"=>rack_input("message=two")).must_equal '{"id":2}'
    body("/notifications/2", "REQUEST_METHOD"=>"POST").must_equal '{"acknowledged":true}'
    body("/page").must_equal "[]"
    body("/poll").must_equal "[]"
    body("/notifications/2", "REQUEST_METHOD"=>"POST").must_equal '{"acknowledged":false}'
    body("/notifications/2", "REQUEST_METHOD"=>"POST").must_equal '{"acknowledged":false}'

    %w'three four five six'.each do |message|
      body("/notifications", "REQUEST_METHOD"=>"POST", "rack.input"=>rack_input("message=#{message}"))
    end

    notifications = JSON.parse(body("/page"))
    notifications.map{|notification| notification["id"]}.must_equal [4, 5, 6]
    notifications.map{|notification| notification["message"]}.must_equal ["four", "five", "six"]
    JSON.parse(body("/poll")).map{|notification| notification["id"]}.must_equal [4, 5, 6]

    body("/notifications/4", "REQUEST_METHOD"=>"POST").must_equal '{"acknowledged":true}'
    body("/notifications/4", "REQUEST_METHOD"=>"POST").must_equal '{"acknowledged":false}'

    body("/notifications", "REQUEST_METHOD"=>"POST", "rack.input"=>rack_input("message=seven")).must_equal '{"id":7}'
    body("/notifications/4", "REQUEST_METHOD"=>"POST").must_equal '{"acknowledged":false}'
    JSON.parse(body("/page")).map{|notification| notification["id"]}.must_equal [5, 6, 7]
    JSON.parse(body("/poll")).map{|notification| notification["id"]}.must_equal [5, 6, 7]
  end

  it "can be used alongside the regular flash plugin" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :flash
      plugin :flash_notifications

      route do |r|
        r.get "flash" do
          flash["message"].inspect
        end

        r.get "notifications" do
          flash_notifications.map{|notification| notification["message"]}.inspect
        end

        flash["message"] = "regular"
        add_flash_notification("persistent")
        "set"
      end
    end

    body.must_equal "set"
    body("/flash").must_equal '"regular"'
    body("/flash").must_equal "nil"
    body("/notifications").must_equal '["persistent"]'
    body("/notifications").must_equal '["persistent"]'
  end

  it "does not acknowledge malformed or fractional IDs" do
    app(:bare) do
      send(*DEFAULT_SESSION_ARGS)
      plugin :flash_notifications

      route do |r|
        r.post do
          ack_flash_notification(r.params["id"]).inspect
        end
      end
    end

    [["id", "1"], ["id", "1.5"], ["id", "-1"], ["id", ""]].each do |params|
      body("/", "REQUEST_METHOD"=>"POST", "rack.input"=>rack_input(params.join("="))).must_equal "false"
    end
  end

  it "requires finite positive limits and separate session keys" do
    proc do
      Class.new(Roda).plugin(:flash_notifications, :retention=>0)
    end.must_raise Roda::RodaError

    proc do
      Class.new(Roda).plugin(:flash_notifications, :retention=>Float::INFINITY)
    end.must_raise Roda::RodaError

    proc do
      Class.new(Roda).plugin(:flash_notifications, :capacity=>0)
    end.must_raise Roda::RodaError

    proc do
      Class.new(Roda).plugin(:flash_notifications, :capacity=>nil)
    end.must_raise Roda::RodaError

    proc do
      Class.new(Roda).plugin(:flash_notifications, :session_key=>"same", :sequence_session_key=>"same")
    end.must_raise Roda::RodaError
  end
end

describe Roda::RodaPlugins::FlashNotifications::NotificationStore do
  before do
    @time = 0
    @clock = lambda{@time}
  end

  def store(notifications=[], sequence=0, retention: 10, capacity: 3)
    Roda::RodaPlugins::FlashNotifications::NotificationStore.new(
      notifications,
      sequence,
      retention,
      capacity,
      @clock
    )
  end

  it "removes expired notifications on read, add, and acknowledgment" do
    notification_store = store([
      {"id"=>1, "message"=>"old", "expires_at"=>10},
      {"id"=>2, "message"=>"current", "expires_at"=>11}
    ])

    @time = 10
    notification_store.to_a.must_equal [{"id"=>2, "message"=>"current", "expires_at"=>11}]

    id = notification_store.add("new")
    id.must_equal 3
    notification_store.to_a.must_equal [
      {"id"=>2, "message"=>"current", "expires_at"=>11},
      {"id"=>3, "message"=>"new", "expires_at"=>20}
    ]
  end

  it "initializes its sequence above existing notification IDs" do
    notification_store = store([{"id"=>9, "message"=>"existing", "expires_at"=>10}], 3)
    notification_store.add("next").must_equal 10
  end

  it "ignores malformed session entries" do
    notification_store = store([
      nil,
      {"id"=>"1", "message"=>"bad", "expires_at"=>10},
      {"id"=>1, "expires_at"=>10},
      {"id"=>2, "message"=>"good", "expires_at"=>10.9}
    ])

    notification_store.to_a.must_equal [{"id"=>2, "message"=>"good", "expires_at"=>10}]
  end

  it "enforces capacity for already stored notifications" do
    notification_store = store([
      {"id"=>1, "message"=>"one", "expires_at"=>10},
      {"id"=>2, "message"=>"two", "expires_at"=>10},
      {"id"=>3, "message"=>"three", "expires_at"=>10},
      {"id"=>4, "message"=>"four", "expires_at"=>10}
    ], 4, capacity: 2)

    notification_store.to_a.must_equal [
      {"id"=>3, "message"=>"three", "expires_at"=>10},
      {"id"=>4, "message"=>"four", "expires_at"=>10}
    ]
    notification_store.sequence.must_equal 4
  end

  it "rejects invalid retention overrides and non-positive IDs" do
    notification_store = store
    proc{notification_store.add("message", 0)}.must_raise Roda::RodaError
    proc{notification_store.add("message", -1)}.must_raise Roda::RodaError
    notification_store.ack(0).must_equal false
    notification_store.ack(-1).must_equal false
  end
end
