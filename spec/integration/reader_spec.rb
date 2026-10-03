# frozen_string_literal: true

RSpec.describe("Reader integration with services and Result") do
  include Dry::Monads[:reader, :result]

  # A tiny gateway used by the service below.
  class EmailGateway
    def initialize(domain:, delivered: [])
      @domain = domain
      @delivered = delivered
    end

    attr_reader :delivered

    def send!(address)
      full = address.include?("@") ? address : "#{address}@#{@domain}"
      @delivered << full
      Dry::Monads.Success(full)
    end
  end

  # A service expressed as a Reader of a Result:
  #
  #   Reader<Env, Result<Symbol, String>>
  #
  # Reader threads the dependencies (the environment) through the steps;
  # Result carries ordinary business failures. The environment is never read
  # while the computation is assembled - Reader#bind only captures a proc -
  # every read happens when the computation is run, so one assembled
  # computation can be run against more than one environment.
  class SubscribeUser
    include Dry::Monads[:reader, :result]

    # The whole pipeline is a single Reader: it captures no environment
    # here and reads it step by step once #run is called. The values
    # travelling through fmap/bind are Results.
    def call(email)
      pipeline(email)
    end

    private

    # Pure validation: no environment required, plain Result.
    def validate(email)
      if email.is_a?(::String) && !email.empty?
        Success(email)
      else
        Failure(:invalid_email)
      end
    end

    def pipeline(email)
      Reader.ask.fmap do |env|
        validate(email).bind do |address|
          if env.fetch(:known_users).include?(address)
            Failure(:already_subscribed)
          else
            env.fetch(:gateway).send!(address)
          end
        end
      end
    end
  end

  subject(:service) { SubscribeUser.new }

  let(:gateway) { EmailGateway.new(domain: "example.com") }
  let(:env) { { gateway: gateway, known_users: [] } }

  describe "a Reader-of-Result service" do
    it "returns Success for a valid, unknown email" do
      result = service.call("anna@example.com").run(env)

      expect(result).to eql(Success("anna@example.com"))
      expect(gateway.delivered).to eql(["anna@example.com"])
    end

    it "returns Failure for an invalid email without touching the gateway" do
      result = service.call("").run(env)

      expect(result).to eql(Failure(:invalid_email))
      expect(gateway.delivered).to be_empty
    end

    it "returns Failure for an already subscribed email" do
      env[:known_users] << "bjorn@example.com"

      result = service.call("bjorn@example.com").run(env)

      expect(result).to eql(Failure(:already_subscribed))
      expect(gateway.delivered).to be_empty
    end

    it "runs the same computation against two different environments" do
      primary = {
        gateway: EmailGateway.new(domain: "primary.test"),
        known_users: []
      }
      secondary = {
        gateway: EmailGateway.new(domain: "secondary.test"),
        known_users: []
      }

      computation = service.call("carla@primary.test")

      expect(computation.run(primary)).to eql(Success("carla@primary.test"))
      expect(computation.run(secondary)).to eql(Success("carla@primary.test"))
      expect(primary[:gateway].delivered).to eql(["carla@primary.test"])
      expect(secondary[:gateway].delivered).to eql(["carla@primary.test"])
    end

    it "reads the environment at run time rather than build time" do
      computation = service.call("dora@example.com")

      # The environment changes between assembling the computation and
      # running it; the read observes the new state.
      env[:known_users] << "dora@example.com"

      expect(computation.run(env)).to eql(Failure(:already_subscribed))
      expect(gateway.delivered).to be_empty
    end

    it "does not convert raised exceptions into Failure" do
      crashing = Object.new
      def crashing.send!(_)
        raise "gateway is down"
      end

      expect {
        service.call("erin@example.com").run(gateway: crashing, known_users: [])
      }.to raise_error(RuntimeError, "gateway is down")
    end

    describe "#local" do
      # Service with a notification step that can be redirected to a
      # different gateway for one sub-computation only.
      let(:welcome_gateway) { EmailGateway.new(domain: "mail.welcome") }

      it "swaps the environment for the scoped sub-computation" do
        gateway_reader = Reader { |e| e.fetch(:gateway) }

        scoped = gateway_reader.local { |e| e.merge(gateway: welcome_gateway) }

        expect(scoped.run(env)).to be(welcome_gateway)
        expect(env.fetch(:gateway)).to be(gateway)
      end

      it "keeps nested local changes from leaking to outer readers" do
        seen_by_nested = nil
        seen_after = nil

        computation =
          Dry::Monads::Reader.ask
                          .local { |e| e.merge(role: :admin) }
                          .local { |e| e.merge(scope: :billing) }
                .fmap { |scoped_env| seen_by_nested = scoped_env }
                .bind {
                  Dry::Monads::Reader.ask.fmap { |outer_env| seen_after = outer_env }
                }

        original = { user: "grace" }
        computation.run(original)

        expect(seen_by_nested).to eql(user: "grace", role: :admin, scope: :billing)
        expect(seen_after).to equal(original)
        expect(seen_after).to eql(user: "grace")
      end

      it "scopes a real delivery to the swapped gateway" do
        # deliver reads :gateway from the env; local redirects only this
        # sub-computation to the welcome gateway.
        deliver = Dry::Monads::Reader.ask.fmap { |e| e.fetch(:gateway).send!("hi@x.test") }
        redirected = deliver.local { |e| e.merge(gateway: welcome_gateway) }

        result = redirected.run(env)

        expect(result).to eql(Success("hi@x.test"))
        expect(welcome_gateway.delivered).to eql(["hi@x.test"])
        expect(gateway.delivered).to be_empty
        expect(env.fetch(:gateway)).to be(gateway)
      end
    end
  end
end
