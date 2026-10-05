# frozen_string_literal: true

require 'timeout'

module Faraday
  class Adapter
    # @example
    #   test = Faraday::Connection.new do
    #     use Faraday::Adapter::Test do |stub|
    #       # Define matcher to match the request
    #       stub.get '/resource.json' do
    #         # return static content
    #         [200, {'Content-Type' => 'application/json'}, 'hi world']
    #       end
    #
    #       # response with content generated based on request
    #       stub.get '/showget' do |env|
    #         [200, {'Content-Type' => 'text/plain'}, env[:method].to_s]
    #       end
    #
    #       # A regular expression can be used as matching filter
    #       stub.get /\A\/items\/(\d+)\z/ do |env, meta|
    #         # in case regular expression is used, an instance of MatchData
    #         # can be received
    #         [200,
    #          {'Content-Type' => 'text/plain'},
    #          "showing item: #{meta[:match_data][1]}"
    #         ]
    #       end
    #
    #      # Test the request body is the same as the stubbed body
    #      stub.post('/bar', 'name=YK&word=call') { [200, {}, ''] }
    #
    #      # You can pass a proc as a stubbed body and check the request body in your way.
    #      # In this case, the proc should return true or false.
    #      stub.post('/foo', ->(request_body) do
    #        JSON.parse(request_body).slice('name') == { 'name' => 'YK' } }) { [200, {}, '']
    #      end
    #
    #       # You can set strict_mode to exactly match the stubbed requests.
    #       stub.strict_mode = true
    #     end
    #   end
    #
    #   resp = test.get '/resource.json'
    #   resp.body # => 'hi world'
    #
    #   resp = test.get '/showget'
    #   resp.body # => 'get'
    #
    #   resp = test.get '/items/1'
    #   resp.body # => 'showing item: 1'
    #
    #   resp = test.get '/items/2'
    #   resp.body # => 'showing item: 2'
    #
    #   resp = test.post '/bar', 'name=YK&word=call'
    #   resp.status # => 200
    #
    #   resp = test.post '/foo', JSON.dump(name: 'YK', created_at: Time.now)
    #   resp.status # => 200
    class Test < Faraday::Adapter
      attr_accessor :stubs

      # A stack of Stubs
      class Stubs
        class NotFound < StandardError
        end

        # Raised when a request belongs to a state-machine workflow but is not
        # available in the machine's current state (e.g. reading a result
        # before submitting a draft, or re-triggering a one-time transition).
        class SequenceError < StandardError
        end

        def initialize(strict_mode: false)
          # { get: [Stub, Stub] }
          @stack = {}
          @consumed = {}
          @state_machines = []
          @strict_mode = strict_mode
          @stubs_mutex = Monitor.new
          yield(self) if block_given?
        end

        def empty?
          @stack.empty?
        end

        # @param env [Faraday::Env]
        def match(env)
          request_method = env[:method]
          stack = @stack[request_method]
          consumed = (@consumed[request_method] ||= [])

          @stubs_mutex.synchronize do
            if stack
              stub, meta = matches?(stack, env)
              if stub
                removed = stack.delete(stub)
                consumed << removed unless removed.nil?
                return stub, meta
              end
            end

            @state_machines.each do |machine|
              result = machine.match(env)
              return result unless result.nil?
            end
          end
          matches?(consumed, env)
        end

        def get(path, headers = {}, &block)
          new_stub(:get, path, headers, &block)
        end

        def head(path, headers = {}, &block)
          new_stub(:head, path, headers, &block)
        end

        def post(path, body = nil, headers = {}, &block)
          new_stub(:post, path, headers, body, &block)
        end

        def put(path, body = nil, headers = {}, &block)
          new_stub(:put, path, headers, body, &block)
        end

        def patch(path, body = nil, headers = {}, &block)
          new_stub(:patch, path, headers, body, &block)
        end

        def delete(path, headers = {}, &block)
          new_stub(:delete, path, headers, &block)
        end

        def options(path, headers = {}, &block)
          new_stub(:options, path, headers, &block)
        end

        # Defines a workflow made of named states and one-time transitions
        # between them. A request is handled by a machine only when its route
        # is registered for the machine's current state, so the same URL can
        # return different responses at different stages of the workflow.
        #
        # State and transition blocks receive the request +env+ and a shared
        # +session+ hash. A transition may read the request and store values
        # in the session for later states to use. Each transition can only be
        # taken once and is consumed atomically, making concurrent competing
        # requests safe: exactly one of them takes the transition while the
        # others raise {SequenceError}.
        #
        # @example create a draft, submit it, then read the result
        #   stubs.state_machine(initial: :drafting) do |fsm|
        #     fsm.state :drafting do |state|
        #       state.post('/drafts') do |_env, session|
        #         session[:draft_id] = '42'
        #         [201, {}, 'draft created']
        #       end
        #
        #       state.transition(:post, '/submit', :ready) do |_env, session|
        #         [202, {}, "submitted draft #{session[:draft_id]}"]
        #       end
        #     end
        #
        #     fsm.state :ready do |state|
        #       state.get('/result') { [200, {}, 'done'] }
        #     end
        #   end
        #
        # @param initial [Symbol] name of the initial state
        # @return [StateMachine]
        def state_machine(initial:, &block)
          machine = StateMachine.new(self, initial, &block)
          @state_machines << machine
          machine
        end

        # Removes all stubs, including the ones that have already been consumed.
        def clear
          @stubs_mutex.synchronize do
            @stack.clear
            @consumed.clear
            @state_machines.clear
          end
        end

        # Raises an error if any of the stubbed calls have not been made.
        def verify_stubbed_calls
          failed_stubs = []
          @stack.each do |method, stubs|
            next if stubs.empty?

            failed_stubs.concat(
              stubs.map do |stub|
                "Expected #{method} #{stub}."
              end
            )
          end
          @state_machines.each do |machine|
            machine.pending_transitions.each do |transition|
              failed_stubs << "Expected #{transition.stub} " \
                             "to transition to #{transition.to.inspect}."
            end
          end
          raise failed_stubs.join(' ') unless failed_stubs.empty?
        end

        # Set strict_mode. If the value is true, this adapter tries to find matched requests strictly,
        # which means that all of a path, parameters, and headers must be the same as an actual request.
        def strict_mode=(value)
          @strict_mode = value
          @stack.each_value do |stubs|
            stubs.each do |stub|
              stub.strict_mode = value
            end
          end
          @state_machines.each { |machine| machine.strict_mode = value }
        end

        # @api private
        #
        # Builds a {Stub} from the arguments of the verb DSL. Regular stubs
        # and state-machine states share this constructor.
        #
        # @return [Stub]
        def build_stub(request_method, path, headers, body, block)
          normalized_path, host =
            if path.is_a?(Regexp)
              path
            else
              [
                Faraday::Utils.normalize_path(path),
                Faraday::Utils.URI(path).host
              ]
            end
          path, query = normalized_path.respond_to?(:split) ? normalized_path.split('?') : normalized_path
          headers = Utils::Headers.new(headers)

          Stub.new(host, path, query, headers, body, @strict_mode, block)
        end

        protected

        def new_stub(request_method, path, headers = {}, body = nil, &block)
          (@stack[request_method] ||= []) <<
            build_stub(request_method, path, headers, body, block)
        end

        # @param stack [Hash]
        # @param env [Faraday::Env]
        def matches?(stack, env)
          stack.each do |stub|
            match_result, meta = stub.matches?(env)
            return stub, meta if match_result
          end
          nil
        end
      end

      # A workflow made of named {State}s and one-time transitions between
      # them. Instances are created through {Stubs#state_machine}.
      class StateMachine
        # @param stubs [Stubs] owning stubs, used to build {Stub}s
        # @param initial [Symbol] name of the initial state
        def initialize(stubs, initial, &block)
          @stubs = stubs
          @initial = initial
          @states = {}
          @order = []
          @session = {}
          @mutex = Monitor.new

          yield(self) if block
          validate!
        end

        # Declares a named state, or reopens an existing one to add more
        # routes.
        #
        # @param name [Symbol]
        # @yieldparam state [State]
        # @return [State]
        def state(name, &block)
          state = @states[name] ||= State.new(name, @stubs)
          @order << name unless @order.include?(name)
          block&.call(state)
          state
        end

        # Moves the machine back to its initial state and clears the session.
        def reset
          @mutex.synchronize do
            @states.each_value(&:reset)
            @current = @initial
            @session = {}
          end
        end

        # @api private
        def strict_mode=(value)
          @states.each_value { |state| state.strict_mode = value }
        end

        # @return [Array<Transition>] transitions that have not been taken yet
        def pending_transitions
          @mutex.synchronize do
            all_states.flat_map(&:pending_transitions)
          end
        end

        # @api private
        #
        # Matches the request against the current state. Returns nil when the
        # current state does not know the route, or [stub, session] otherwise.
        # Raises {Stubs::SequenceError} when the route exists but cannot be
        # served in the current state.
        def match(env)
          @mutex.synchronize do
            stub, meta, target = @states.fetch(current_state).match(env, @session)
            if stub
              advance_to(target) if target
              return [stub, meta]
            end

            consumed = all_states
                       .flat_map(&:consumed_transitions)
                       .find { |transition| transition.stub.matches?(env).first }
            raise_already_taken(env, consumed) if consumed

            future = all_states.find do |state|
              state.name != current_state && state.knows_route?(env)
            end
            raise_not_reached(env, future) if future

            nil
          end
        end

        private

        def all_states
          @order.map { |name| @states[name] }
        end

        def current_state
          @current ||= @initial
        end

        def advance_to(name)
          unless @states.key?(name)
            raise ArgumentError, "unknown state #{name.inspect}"
          end

          @current = name
        end

        def raise_already_taken(env, transition)
          raise(
            Stubs::SequenceError,
            "#{env[:method].to_s.upcase} #{env[:url]} is a one-time " \
            "transition to #{transition.to.inspect} that has already been " \
            'taken; the machine is now in state ' \
            "#{current_state.inspect}."
          )
        end

        def raise_not_reached(env, state)
          raise(
            Stubs::SequenceError,
            "#{env[:method].to_s.upcase} #{env[:url]} is only available " \
            "in state #{state.name.inspect}, but the machine is still in " \
            "state #{current_state.inspect}. Complete the preceding steps first."
          )
        end

        def validate!
          unless @states.key?(@initial)
            known = @order.map(&:inspect).join(', ')
            raise ArgumentError,
                  "unknown initial state #{@initial.inspect}, known states: #{known}"
          end

          all_states.each do |state|
            state.transitions.each do |transition|
              unless @states.key?(transition.to)
                raise ArgumentError,
                      "transition #{transition.stub} targets unknown " \
                      "state #{transition.to.inspect}"
              end
            end
          end
        end

        # A named stage of a {StateMachine}.
        class State
          # A one-time move from one {State} to another.
          Transition = Struct.new(:stub, :to, :guard)

          attr_reader :name, :transitions, :consumed_transitions

          def initialize(name, stubs)
            @name = name
            @stubs = stubs
            @entries = []
            @transitions = []
            @consumed_transitions = []
          end

          # Registers a repeatable handler for the current state.
          def get(path, headers = {}, &block)
            register(:get, path, headers, nil, block)
          end

          def head(path, headers = {}, &block)
            register(:head, path, headers, nil, block)
          end

          def post(path, body = nil, headers = {}, &block)
            register(:post, path, headers, body, block)
          end

          def put(path, body = nil, headers = {}, &block)
            register(:put, path, headers, body, block)
          end

          def patch(path, body = nil, headers = {}, &block)
            register(:patch, path, headers, body, block)
          end

          def delete(path, headers = {}, &block)
            register(:delete, path, headers, nil, block)
          end

          def options(path, headers = {}, &block)
            register(:options, path, headers, nil, block)
          end

          # Registers a one-time transition to another state. The first
          # request matching the stub takes the transition, receives the
          # block response and moves the machine to +to+. Competing requests
          # are resolved atomically, so the transition is taken at most once.
          #
          # @param method [Symbol] HTTP verb, e.g. +:post+
          # @param path [String, Regexp] request path to match
          # @param to [Symbol] target state name
          # @param headers [Hash] request headers to match
          # @param body [Object] request body to match
          # @param guard [#call, nil] optional proc receiving the request env;
          #   the transition is taken only when it returns a truthy value
          # @yieldparam env [Faraday::Env] request environment
          # @yieldparam session [Hash] shared workflow session
          def transition(method, path, to, headers: {}, body: nil, guard: nil, &block)
            raise ArgumentError, 'a response block is required' unless block

            stub = @stubs.build_stub(method, path, headers, body, block)
            transition = Transition.new(stub, to, guard)
            @entries << transition
            @transitions << transition
            transition
          end

          # @api private
          def reset
            @entries.concat(@consumed_transitions)
            @consumed_transitions.clear
          end

          # @api private
          def strict_mode=(value)
            (@entries + @consumed_transitions).each do |entry|
              entry_stub(entry).strict_mode = value
            end
          end

          # @api private
          def pending_transitions
            @entries.grep(Transition)
          end

          # @api private
          def knows_route?(env)
            (@entries + @consumed_transitions).any? do |entry|
              entry_stub(entry).matches?(env).first
            end
          end

          # @api private
          #
          # @return [Array, nil] +[stub, session, target_state]+ on match,
          #   nil when the route is unknown to this state
          def match(env, session)
            usable = find_usable(env)
            known = !usable.nil? || knows_route?(env)

            return nil unless known
            return use(usable, session) if usable

            raise_sequence_error(env)
          end

          private

          def register(method, path, headers, body, block)
            raise ArgumentError, 'a response block is required' unless block

            stub = @stubs.build_stub(method, path, headers, body, block)
            @entries << stub
            stub
          end

          def find_usable(env)
            @entries.each do |entry|
              stub = entry_stub(entry)
              matched, meta = stub.matches?(env)
              next unless matched
              next if entry.is_a?(Transition) && guard_rejects?(entry, env)

              return [entry, stub, meta]
            end
            nil
          end

          def guard_rejects?(transition, env)
            transition.guard && !transition.guard.call(env)
          end

          def use(usable, session)
            entry, stub, meta = usable
            session.merge!(meta)

            if entry.is_a?(Transition)
              @entries.delete(entry)
              @consumed_transitions << entry
              [stub, session, entry.to]
            else
              [stub, session, nil]
            end
          end

          def raise_sequence_error(env)
            reason = if @consumed_transitions.any? { |t| t.stub.matches?(env).first }
                       'the one-time transition has already been taken'
                     else
                       'the transition condition was not met'
                     end

            raise(
              Stubs::SequenceError,
              "#{env[:method].to_s.upcase} #{env[:url]} is not available " \
              "in state #{name.inspect}: #{reason}. " \
              'Perform the workflow steps in order.'
            )
          end

          def entry_stub(entry)
            entry.is_a?(Transition) ? entry.stub : entry
          end
        end
      end

      # Stub request
      Stub = Struct.new(:host, :path, :query, :headers, :body, :strict_mode, :block) do
        # @param env [Faraday::Env]
        def matches?(env)
          request_host = env[:url].host
          request_path = Faraday::Utils.normalize_path(env[:url].path)
          request_headers = env.request_headers
          request_body = env[:body]

          # meta is a hash used as carrier
          # that will be yielded to consumer block
          meta = {}
          [(host.nil? || host == request_host) &&
            path_match?(request_path, meta) &&
            params_match?(env) &&
            body_match?(request_body) &&
            headers_match?(request_headers), meta]
        end

        def path_match?(request_path, meta)
          if path.is_a?(Regexp)
            !!(meta[:match_data] = path.match(request_path))
          else
            path == request_path
          end
        end

        # @param env [Faraday::Env]
        def params_match?(env)
          request_params = env[:params]
          params = env.params_encoder.decode(query) || {}

          if strict_mode
            return Set.new(params) == Set.new(request_params)
          end

          params.keys.all? do |key|
            request_params[key] == params[key]
          end
        end

        def headers_match?(request_headers)
          if strict_mode
            headers_with_user_agent = headers.dup.tap do |hs|
              # NOTE: Set User-Agent in case it's not set when creating Stubs.
              #       Users would not want to set Faraday's User-Agent explicitly.
              hs[:user_agent] ||= Connection::USER_AGENT
            end
            return Set.new(headers_with_user_agent) == Set.new(request_headers)
          end

          headers.keys.all? do |key|
            request_headers[key] == headers[key]
          end
        end

        def body_match?(request_body)
          return true if body.to_s.empty?

          case body
          when Proc
            body.call(request_body)
          else
            request_body == body
          end
        end

        def to_s
          "#{path} #{body}"
        end
      end

      def initialize(app, stubs = nil, &block)
        super(app)
        @stubs = stubs || Stubs.new
        configure(&block) if block
      end

      def configure
        yield(stubs)
      end

      # @param env [Faraday::Env]
      def call(env)
        super

        env.request.params_encoder ||= Faraday::Utils.default_params_encoder
        env[:params] = env.params_encoder.decode(env[:url].query) || {}
        stub, meta = stubs.match(env)

        unless stub
          raise Stubs::NotFound, "no stubbed request for #{env[:method]} " \
                                 "#{env[:url]} #{env[:body]} #{env[:headers]}"
        end

        block_arity = stub.block.arity
        params = if block_arity >= 0
                   [env, meta].take(block_arity)
                 else
                   [env, meta]
                 end

        timeout = request_timeout(:open, env[:request])
        timeout ||= request_timeout(:read, env[:request])

        status, headers, body =
          if timeout
            ::Timeout.timeout(timeout, Faraday::TimeoutError) do
              stub.block.call(*params)
            end
          else
            stub.block.call(*params)
          end

        # We need to explicitly pass `reason_phrase = nil` here to avoid keyword args conflicts.
        #   See https://github.com/lostisland/faraday/issues/1444
        # TODO: remove `nil` explicit reason_phrase once Ruby 3.0 becomes minimum req. version
        save_response(env, status, body, headers, nil)

        @app.call(env)
      end
    end
  end
end

Faraday::Adapter.register_middleware(test: Faraday::Adapter::Test)
