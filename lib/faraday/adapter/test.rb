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

        class InvalidStateTransition < StandardError
        end

        class TransitionInProgress < InvalidStateTransition
        end

        class TransitionConsumed < InvalidStateTransition
        end

        class State
          attr_reader :name, :stubs

          def initialize(name, stubs)
            @name = name
            @stubs_owner = stubs
            @stubs = []
          end

          def get(path, headers = {}, **options, &block)
            add_state_stub(:get, path, headers, nil, options, block)
          end

          def head(path, headers = {}, **options, &block)
            add_state_stub(:head, path, headers, nil, options, block)
          end

          def post(path, body = nil, headers = {}, **options, &block)
            add_state_stub(:post, path, headers, body, options, block)
          end

          def put(path, body = nil, headers = {}, **options, &block)
            add_state_stub(:put, path, headers, body, options, block)
          end

          def patch(path, body = nil, headers = {}, **options, &block)
            add_state_stub(:patch, path, headers, body, options, block)
          end

          def delete(path, headers = {}, **options, &block)
            add_state_stub(:delete, path, headers, nil, options, block)
          end

          def options(path, headers = {}, **options, &block)
            add_state_stub(:options, path, headers, nil, options, block)
          end

          private

          def add_state_stub(request_method, path, headers, body, options, block)
            @stubs_owner.add_state_stub(
              name, request_method, path, headers, body,
              options.fetch(:transition, nil), block
            )
          end
        end

        class StateContext < Hash
          attr_reader :state, :target

          def initialize(state, data, meta)
            super()
            @state = state
            @transition_data = data.dup.merge(meta)
            @meta = meta
            @target = nil
            replace(@transition_data.merge(@meta))
          end

          def update(data)
            @transition_data.merge!(data.to_h)
            super
            self
          end
          alias merge! update

          def set(key, value)
            @transition_data[key] = value
            self[key] = value
            self
          end

          def []=(key, value)
            @transition_data[key] = value
            super
          end

          def transition_to(target, data = nil, **keyword_data)
            target = target.to_sym
            values = data ? data.to_h.merge(keyword_data) : keyword_data

            if @target && @target != target
              raise ArgumentError, "transition target is already set to #{@target.inspect}"
            end

            @target = target
            @transition_data.merge!(values)
            merge!(values)
            self
          end

          def transition_data
            @transition_data.dup
          end
        end

        TransitionClaim = Struct.new(:stub, :from, keyword_init: true)

        def initialize(strict_mode: false)
          # { get: [Stub, Stub] }
          @stack = {}
          @consumed = {}
          @states = {}
          @initial_state = nil
          @current_state = nil
          @state_data = Hash.new { |data, state| data[state] = {} }
          @pending_transition = nil
          @strict_mode = strict_mode
          @stubs_mutex = Monitor.new
          yield(self) if block_given?
        end

        def empty?
          @stubs_mutex.synchronize { @stack.empty? && @states.empty? }
        end

        attr_reader :current_state

        def initial_state(name = nil)
          return @initial_state if name.nil?

          @stubs_mutex.synchronize do
            @initial_state = name.to_sym
            @current_state = name.to_sym
          end
        end
        alias initial_state= initial_state

        def state(name, initial: nil, &block)
          name = name.to_sym
          state = nil

          @stubs_mutex.synchronize do
            state = @states[name] ||= State.new(name, self)
            if initial == true || (@initial_state.nil? && initial != false)
              @initial_state = name
              @current_state = name
            end
            @current_state ||= @initial_state
            block&.call(state)
          end

          state
        end

        def add_state_stub(state_name, request_method, path, headers, body, transition, block)
          stub = build_stub(path, headers, body, block, StateStub)
          stub.state_name = state_name.to_sym
          stub.request_method = request_method
          stub.transition_target = transition == true ? true : transition&.to_sym

          @stubs_mutex.synchronize do
            @states[state_name.to_sym]&.stubs << stub
          end
          stub
        end

        # @param env [Faraday::Env]
        def match(env)
          @stubs_mutex.synchronize do
            stub, meta = match_stateless_stub?(env)
            return stub, meta if stub

            match_state_stub?(env)
          end
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

        # Removes all stubs, including the ones that have already been consumed.
        def clear
          @stubs_mutex.synchronize do
            @stack.clear
            @consumed.clear
            @states.clear
            @initial_state = nil
            @current_state = nil
            @state_data.clear
            @pending_transition = nil
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
          @states.each_value do |state|
            state.stubs.each do |stub|
              next unless stub.is_a?(StateStub) && stub.transition? && !stub.claimed?

              failed_stubs << "Expected state transition #{stub.state_name} #{method_for(stub)} #{stub}."
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
          @states.each_value do |state|
            state.stubs.each { |stub| stub.strict_mode = value }
          end
        end

        protected

        def new_stub(request_method, path, headers = {}, body = nil, &block)
          stub = build_stub(path, headers, body, block)
          (@stack[request_method] ||= []) << stub
          stub
        end

        def build_stub(path, headers, body, block, stub_class = Stub)
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

          stub_class.new(host, path, query, headers, body, @strict_mode, block)
        end

        def match_stateless_stub?(env)
          request_method = env[:method]
          return nil unless @stack.key?(request_method)

          stack = @stack[request_method]
          consumed = (@consumed[request_method] ||= [])

          stub, meta = matches?(stack, env)
          if stub
            removed = stack.delete(stub)
            consumed << removed unless removed.nil?
            return stub, meta
          end

          matches?(consumed, env)
        end

        def match_state_stub?(env)
          return nil if @states.empty?

          state = @states[@current_state]
          unless state
            raise InvalidStateTransition, "current state #{@current_state.inspect} is not defined"
          end

          if transition_in_progress?(env)
            raise TransitionInProgress, pending_transition_message(@pending_transition.stub, env)
          end
          stub, meta = matching_stub(state.stubs, env)
          if stub
            if stub.transition?
              validate_transition_target!(stub)
              claim_transition(stub)
              context = state_context(meta)
              context.transition_to(stub.transition_target) if stub.transition_target.is_a?(Symbol)
              return transition_wrapper(stub, context), context
            end

            return stub, state_context(meta)
          end

          consumed = consumed_transition_stub(env)
          if consumed
            raise TransitionConsumed, consumed_transition_message(consumed, env)
          end

          available_states = states_matching(env)
          return nil if available_states.empty?

          raise InvalidStateTransition, invalid_state_message(env, available_states)
        end

        def matching_stub(stubs, env)
          stubs.each do |stub|
            next if stub.claimed?
            next unless stub.request_method == env[:method]

            match_result, meta = stub.matches?(env)
            return stub, meta if match_result
          end
          nil
        end

        def states_matching(env)
          @states.filter_map do |name, state|
            state.stubs.any? do |stub|
              !stub.claimed? &&
                stub.request_method == env[:method] &&
                stub.matches?(env).first
            end && name
          end
        end

        def claim_transition(stub)
          if @pending_transition
            raise TransitionInProgress, pending_transition_message(@pending_transition.stub, env)
          end

          stub.claim!
          @pending_transition = TransitionClaim.new(stub: stub, from: @current_state)
        end

        def transition_in_progress?(env)
          pending = @pending_transition
          pending &&
            pending.stub.request_method == env[:method] &&
            pending.stub.matches?(env).first
        end

        def consumed_transition_stub(env)
          @states.each_value do |state|
            state.stubs.each do |stub|
              next unless stub.is_a?(StateStub) &&
                            stub.claimed? &&
                            stub.request_method == env[:method]

              return stub if stub.matches?(env).first
            end
          end
          nil
        end

        def validate_transition_target!(stub)
          target = stub.transition_target
          return unless target.is_a?(Symbol)
          return if @states.key?(target)

          raise InvalidStateTransition, "unknown transition target state #{target.inspect}"
        end

        def state_context(meta)
          StateContext.new(
            @current_state,
            @state_data[@current_state] || {},
            meta
          )
        end

        def transition_wrapper(stub, context)
          claim = @pending_transition
          block = stub.block
          wrapper = lambda do |env, _context|
            begin
              response = block.call(*block_arguments(block, env, context))
              commit_transition(claim, context)
              response
            rescue StandardError
              rollback_transition(claim)
              raise
            end
          end

          StateStub.new(
            stub.host, stub.path, stub.query, stub.headers, stub.body,
            stub.strict_mode, wrapper
          ).tap do |wrapper_stub|
            wrapper_stub.state_name = stub.state_name
            wrapper_stub.request_method = stub.request_method
            wrapper_stub.transition_target = stub.transition_target
          end
        end

        def block_arguments(block, env, context)
          case block.arity
          when 0 then []
          when 1 then [env]
          else [env, context]
          end
        end

        def commit_transition(claim, context)
          @stubs_mutex.synchronize do
            return unless @pending_transition == claim

            target = context.target
            unless target
              rollback_transition(claim)
              raise InvalidStateTransition, 'state transition did not specify a target state'
            end
            unless @states.key?(target)
              rollback_transition(claim)
              raise InvalidStateTransition, "unknown transition target state #{target.inspect}"
            end

            @state_data[target] = context.transition_data.dup
            @current_state = target
            @pending_transition = nil
          end
        end

        def rollback_transition(claim)
          @stubs_mutex.synchronize do
            return unless @pending_transition == claim

            claim.stub.release!
            @pending_transition = nil
          end
        end

        def pending_transition_message(stub, env)
          "a one-time transition from #{@pending_transition&.from.inspect} for " \
            "#{stub.request_method.to_s.upcase} #{env[:url]} is already in progress"
        end

        def consumed_transition_message(stub, env)
          "one-time transition from #{stub.state_name.inspect} for " \
            "#{stub.request_method.to_s.upcase} #{env[:url]} has already been consumed"
        end

        def invalid_state_message(env, available_states)
          "#{env[:method].to_s.upcase} #{env[:url]} is not available in current state " \
            "#{@current_state.inspect}. It is available in #{available_states.inspect[1..-2]}."
        end

        def method_for(stub)
          stub.request_method.to_s.upcase
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

      class Stubs::StateStub < Stub
        attr_accessor :state_name, :request_method, :transition_target

        def initialize(*)
          super
          @claimed = false
        end

        def claimed?
          @claimed
        end

        def claim!
          @claimed = true
        end

        def release!
          @claimed = false
        end

        def transition?
          !transition_target.nil? && transition_target != false
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
