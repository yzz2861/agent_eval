# frozen_string_literal: true

require_relative 'constants'
require_relative 'utils'
require_relative 'body_proxy'

module Rack

  # = Sendfile
  #
  # The Sendfile middleware intercepts responses whose body is being
  # served from a file and replaces it with a server specific x-sendfile
  # header. The web server is then responsible for writing the file contents
  # to the client. This can dramatically reduce the amount of work required
  # by the Ruby backend and takes advantage of the web server's optimized file
  # delivery code.
  #
  # In order to take advantage of this middleware, the response body must
  # respond to +to_path+ and the request must include an `x-sendfile-type`
  # header. Rack::Files and other components implement +to_path+ so there's
  # rarely anything you need to do in your application. The `x-sendfile-type`
  # header is typically set in your web servers configuration. The following
  # sections attempt to document
  #
  # === Nginx
  #
  # Nginx supports the `x-accel-redirect` header. This is similar to `x-sendfile`
  # but requires parts of the filesystem to be mapped into a private URL
  # hierarchy.
  #
  # The following example shows the Nginx configuration required to create
  # a private "/files/" area, enable `x-accel-redirect`, and pass the special
  # `x-accel-mapping` header to the backend:
  #
  #   location ~ /files/(.*) {
  #     internal;
  #     alias /var/www/$1;
  #   }
  #
  #   location / {
  #     proxy_redirect     off;
  #
  #     proxy_set_header   Host                $host;
  #     proxy_set_header   X-Real-IP           $remote_addr;
  #     proxy_set_header   X-Forwarded-For     $proxy_add_x_forwarded_for;
  #
  #     proxy_set_header   x-accel-mapping     /var/www/=/files/;
  #
  #     proxy_pass         http://127.0.0.1:8080/;
  #   }
  #
  # The `x-accel-mapping` header should specify the location on the file system,
  # followed by an equals sign (=), followed name of the private URL pattern
  # that it maps to. The middleware performs a case-insensitive substitution on the
  # resulting path.
  #
  # To enable `x-accel-redirect`, you must configure the middleware explicitly:
  #
  #   use Rack::Sendfile, "x-accel-redirect"
  #
  # For security reasons, the `x-sendfile-type` header from requests is ignored.
  # The sendfile variation must be set via the middleware constructor.
  #
  # See Also: https://www.nginx.com/resources/wiki/start/topics/examples/xsendfile
  #
  # === lighttpd
  #
  # Lighttpd has supported some variation of the `x-sendfile` header for some
  # time, although only recent version support `x-sendfile` in a reverse proxy
  # configuration.
  #
  #   $HTTP["host"] == "example.com" {
  #      proxy-core.protocol = "http"
  #      proxy-core.balancer = "round-robin"
  #      proxy-core.backends = (
  #        "127.0.0.1:8000",
  #        "127.0.0.1:8001",
  #        ...
  #      )
  #
  #      proxy-core.allow-x-sendfile = "enable"
  #      proxy-core.rewrite-request = (
  #        "x-sendfile-type" => (".*" => "x-sendfile")
  #      )
  #    }
  #
  # See Also: http://redmine.lighttpd.net/wiki/lighttpd/Docs:ModProxyCore
  #
  # === Apache
  #
  # `x-sendfile` is supported under Apache 2.x using a separate module:
  #
  # https://tn123.org/mod_xsendfile/
  #
  # Once the module is compiled and installed, you can enable it using
  # XSendFile config directive:
  #
  #   RequestHeader Set x-sendfile-type x-sendfile
  #   ProxyPassReverse / http://localhost:8001/
  #   XSendFile on
  #
  # === Mapping parameter
  #
  # The third parameter allows for an overriding extension of the
  # `x-accel-mapping` header. Mappings should be provided in tuples of internal to
  # external. The internal values may contain regular expression syntax, they
  # will be matched with case indifference.
  #
  # When `x-accel-redirect` is explicitly enabled via the variation parameter,
  # and no application-level mappings are provided, the middleware will read
  # the `x-accel-mapping` header from the proxy. This allows nginx to control
  # the path mapping without requiring application-level configuration.
  #
  # === Security
  #
  # For security reasons, the `x-sendfile-type` header from HTTP requests is
  # ignored. The sendfile variation must be explicitly configured via the
  # middleware constructor to prevent information disclosure vulnerabilities
  # where attackers could bypass proxy restrictions.
  #
  # === Strict mapping mode
  #
  # Strict mode turns the mappings parameter into an allowlist: the
  # application declares exactly which directories may be served and which
  # internal URI prefixes they map to, and request headers (such as
  # `x-accel-mapping`) can never widen those mappings.
  #
  #   use Rack::Sendfile, "x-accel-redirect",
  #     [["/var/www/files/", "/files/"]],
  #     strict: true, on_miss: :reject
  #
  # In strict mode, before any mapping happens the file's real location is
  # resolved with `File.realpath`, so symlinks that point outside a declared
  # directory are detected. Roots are compared with a directory-boundary-aware
  # prefix check, so a root of `/var/www/files` does not also match
  # `/var/www/files-evil`. The resulting header value is percent-encoded
  # exactly once (spaces, non-ASCII and `%` characters in filenames are
  # safe), never contains control characters such as newlines, and is never
  # decoded again by the middleware.
  #
  # When the real path does not fall under any declared root, the `on_miss`
  # option decides what happens:
  #
  # * `:fallback` (default) - serve the response body normally, as if the
  #   middleware were not involved.
  # * `:reject` - close the original body and respond with `403 Forbidden`.
  #
  # Strict mode also applies the declared roots to `x-sendfile` and
  # `x-lighttpd-send-file`: files outside the roots are never handed to the
  # proxy.

  class Sendfile
    # Valid values for the +on_miss+ option in strict mode.
    ON_MISS_ACTIONS = [:fallback, :reject].freeze

    def initialize(app, variation = nil, mappings = [], strict: false, on_miss: :fallback)
      unless ON_MISS_ACTIONS.include?(on_miss)
        raise ArgumentError, "invalid on_miss: #{on_miss.inspect} (expected one of #{ON_MISS_ACTIONS.map(&:inspect).join(', ')})"
      end

      @app = app
      @variation = variation
      @strict = strict
      @on_miss = on_miss
      @mappings = mappings.map do |internal, external|
        [/\A#{internal}/i, external]
      end
      @strict_mappings = mappings
    end

    def call(env)
      _, headers, body = response = @app.call(env)

      if body.respond_to?(:to_path)
        case type = variation(env)
        when /x-accel-redirect/i
          if @strict
            return handle_strict_miss(env, response, body) unless url = strict_map_path(body.to_path)

            set_sendfile_headers(headers, type, url, response, body)
          else
            path = ::File.expand_path(body.to_path)
            if url = map_accel_path(env, path)
              set_sendfile_headers(headers, type, url, response, body)
            else
              env[RACK_ERRORS].puts "x-accel-mapping header missing"
            end
          end
        when /x-sendfile|x-lighttpd-send-file/i
          if @strict
            return handle_strict_miss(env, response, body) unless path = strict_real_path(body.to_path)

            set_sendfile_headers(headers, type, path, response, body, escape: false)
          else
            path = ::File.expand_path(body.to_path)
            set_sendfile_headers(headers, type, path, response, body, escape: false)
          end
        when '', nil
        else
          env[RACK_ERRORS].puts "Unknown x-sendfile variation: #{type.inspect}"
        end
      end
      response
    end

    private

    def set_sendfile_headers(headers, type, value, response, body, escape: true)
      headers[CONTENT_LENGTH] = '0'
      # '?' must be percent-encoded because it is not query string but a part of path
      headers[type.downcase] = escape ? ::Rack::Utils.escape_path(value).gsub('?', '%3F') : value
      obody = body
      response[2] = Rack::BodyProxy.new([]) do
        obody.close if obody.respond_to?(:close)
      end
    end

    # Strict mode miss handling: either serve the body normally, or reject
    # the request outright. The original body is always left in a state the
    # server can close (fallback) or is closed immediately (reject).
    def handle_strict_miss(env, response, body)
      case @on_miss
      when :reject
        body.close if body.respond_to?(:close)
        message = "Forbidden\n"
        [403, { CONTENT_TYPE => 'text/plain', CONTENT_LENGTH => message.bytesize.to_s }, [message]]
      else
        env[RACK_ERRORS].puts "sendfile: #{body.to_path.inspect} is not under any declared root, serving normally"
        response
      end
    end

    # Resolve the real location of +path+, refusing anything containing
    # control characters (which could inject extra response headers) and
    # anything not under one of the declared roots. Returns the real path,
    # or nil when the file must not be sent by the proxy.
    #
    # Paths are handled as raw bytes: filesystem paths and configured roots
    # may carry different string encodings, and byte comparison is both
    # encoding-safe and what the operating system actually matches on.
    def strict_real_path(path)
      return nil if path.nil?

      path = path.to_s
      return nil if path.match?(/[\x00-\x1f\x7f]/n)

      real = begin
        ::File.realpath(path)
      rescue SystemCallError
        return nil
      end.b

      @strict_mappings.any? { |internal, _| under_root?(real, internal) } ? real : nil
    end

    # Map +path+ onto the declared internal URI prefix of the first root
    # that contains it. Returns nil when the file is outside every root.
    def strict_map_path(path)
      return nil unless real = strict_real_path(path)

      @strict_mappings.each do |internal, external|
        prefix = root_prefix(internal)
        next unless prefix && real.start_with?(prefix)

        return external.to_s.b + real.byteslice(prefix.length..)
      end
      nil
    end

    # Directory-boundary-aware check: +path+ must be strictly inside the
    # real location of +root+, so "/var/www/files-evil/x" never matches a
    # declared root of "/var/www/files".
    def under_root?(path, root)
      !!(prefix = root_prefix(root)) && path.start_with?(prefix)
    end

    # Real path of a declared root, with a trailing file separator so prefix
    # comparisons cannot collide with sibling directories sharing a name
    # prefix. Returns nil when the root does not exist.
    def root_prefix(root)
      real = begin
        ::File.realpath(root.to_s)
      rescue SystemCallError
        return nil
      end.b
      real.end_with?(::File::SEPARATOR) ? real : "#{real}#{::File::SEPARATOR}"
    end

    def variation(env)
      # Note: HTTP_X_SENDFILE_TYPE is intentionally NOT read for security reasons.
      # Attackers could use this header to enable x-accel-redirect and bypass proxy restrictions.
      @variation || env['sendfile.type']
    end

    def x_accel_mapping(env)
      # Only allow header when:
      # 1. `x-accel-redirect` is explicitly enabled via constructor.
      # 2. No application-level mappings are configured.
      return nil unless @variation =~ /x-accel-redirect/i
      return nil if @mappings.any?
      
      env['HTTP_X_ACCEL_MAPPING']
    end

    def map_accel_path(env, path)
      if mapping = @mappings.find { |internal, _| internal =~ path }
        return path.sub(*mapping)
      elsif mapping = x_accel_mapping(env)
        # Safe to use header: explicit config + no app mappings:
        mapping.split(',').map(&:strip).each do |m|
          internal, external = m.split('=', 2).map(&:strip)
          new_path = path.sub(/\A#{Regexp.escape(internal)}/i, external)
          return new_path unless path == new_path
        end

        return path
      end
    end
  end
end
