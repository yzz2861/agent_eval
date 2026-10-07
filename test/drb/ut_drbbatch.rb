# frozen_string_literal: false
require 'drb/drb'
require 'drb/extserv'

module DRbTests

  class BatchProfile
    include DRbUndumped

    def initialize(account_id, log)
      @account_id = account_id
      @log = log
    end

    def summary
      @log << :summary
      "summary of account #{@account_id}"
    end

    def explode
      @log << :explode
      raise "boom from account #{@account_id}"
    end
  end

  class BatchAccount
    include DRbUndumped

    def initialize(id, log)
      @id = id
      @log = log
    end

    def profile
      @log << :profile
      BatchProfile.new(@id, @log)
    end
  end

  class BatchFront
    def initialize
      @log = []
    end

    # Returns the names of the methods that have actually been invoked
    # on the server side, in invocation order.
    def call_log
      @log.dup
    end

    def reset_log
      @log.clear
      true
    end

    def get_account(id)
      @log << :get_account
      BatchAccount.new(id, @log)
    end

    def heartbeat
      @log << :heartbeat
      :pong
    end

    def tagged(value, tag)
      @log << :tagged
      [value, tag]
    end
  end
end

if __FILE__ == $0
  def ARGV.shift
    it = super()
    raise "usage: #{$0} <manager-uri> <name>" unless it
    it
  end

  DRb.start_service('druby://localhost:0', DRbTests::BatchFront.new)
  es = DRb::ExtServ.new(ARGV.shift, ARGV.shift)
  DRb.thread.join
  es.stop_service if es.alive?
end
