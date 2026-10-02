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
  # `x-accel-mapping` header. Mappings should be provided in tuples of a
  # filesystem directory to an internal proxy URI prefix. The non-strict internal
  # values may contain regular expression syntax; they are matched with case
  # indifference.
  #
  # Pass <tt>strict_mappings: true</tt> with <tt>x-accel-redirect</tt> (or
  # without a variation) to declare the complete set of directories that may
  # be delegated to the proxy. In that mode the
  # `x-accel-mapping` request header is always ignored and the real path of each
  # response file is checked before a mapping is applied. Symbolic links are
  # resolved, so a link which points outside of every declared directory cannot
  # produce an `x-accel-redirect` header.
  #
  # <tt>on_unmatched:</tt> is required in strict mode and must be either:
  #
  # * +:fallback+ - return the original Rack response unchanged.
  # * +:reject+ - close the original body and return a 403 response.
  #
  # Mappings use directory boundaries, which avoids +/srv/files+ matching
  # +/sail/files-secret+. The longest matching directory is used for nested
  # mappings. URI prefixes must already be valid URI paths; file names are
  # percent-encoded once, including non-ASCII characters, spaces, and percent
  # characters.
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

  class Sendfile
    def initialize(
      app,
      variation = nil,
      mappings = [],
      strict_mappings: false,
      on_unmatched: nil
    )
      @app = app
      @variation = strict_mappings ? variation || 'x-accel-redirect' : variation
      @mappings = mappings.map do |internal, external|
        [/\A#{internal}/i, external]
      end

      @strict_mapping_enabled = strict_mappings
      @on_unmatched = on_unmatched

      if @strict_mapping_enabled
        unless variation.nil? || variation.to_s.downcase == 'x-accel-redirect'
          raise ArgumentError, "strict mappings require x-accel-redirect"
        end

        unless [:fallback, :reject].include?(on_unmatched)
          raise ArgumentError, "on_unmatched must be :fallback or :reject"
        end

        if mappings.empty?
          raise ArgumentError, "strict mappings require at least one mapping"
        end

        @strict_mappings = mappings.map do |internal, external|
          root = ::File.realpath(::File.expand_path(internal))
          prefix = validate_accel_prefix(external)

          unless ::File.directory?(root)
            raise ArgumentError, "not a directory: #{internal}"
          end

          [root, prefix]
        end

        if @strict_mappings.map(&:first).uniq.size != @strict_mappings.size
          raise ArgumentError, "duplicate strict mapping directory"
        end

        if @strict_mappings.map(&:last).uniq.size != @strict_mappings.size
          raise ArgumentError, "duplicate strict mapping URI prefix"
        end
      end
    end

    def call(env)
      _, headers, body = response = @app.call(env)

      if body.respond_to?(:to_path)
        case type = variation(env)
        when /x-accel-redirect/i
          if @strict_mappings
            mapped_path = strict_accel_path(body)

            if mapped_path
              replace_with_sendfile(response, headers, body, type, mapped_path)
            elsif @on_unmatched == :reject
              body.close if body.respond_to?(:close)
              return [403, { CONTENT_TYPE => 'text/plain', CONTENT_LENGTH => '0' }, []]
            end
          else
            path = ::File.expand_path(body.to_path)
            if url = map_accel_path(env, path)
              url = ::Rack::Utils.escape_path(url).gsub('?', '%3F')
              replace_with_sendfile(response, headers, body, type, url)
            else
              env[RACK_ERRORS].puts "x-accel-mapping header missing"
            end
          end
        when /x-sendfile|x-lighttpd-send-file/i
          path = ::File.expand_path(body.to_path)
          headers[CONTENT_LENGTH] = '0'
          headers[type.downcase] = path
          obody = body
          response[2] = Rack::BodyProxy.new([]) do
            obody.close if obody.respond_to?(:close)
          end
        when '', nil
        else
          env[RACK_ERRORS].puts "Unknown x-sendfile variation: #{type.inspect}"
        end
      end
      response
    end

    private

    def validate_accel_prefix(prefix)
      unless prefix.is_a?(::String) && prefix.start_with?('/') &&
             prefix.valid_encoding? &&
             !prefix.match?(/[\p{Cntrl}\s?#]/) &&
             !prefix.match?(%r{//|%2f|%5c}i) &&
             !prefix.match?(/%(?![0-9a-fA-F]{2})/) &&
             !prefix.match?(/%0[ad]/i)
        raise ArgumentError, "invalid x-accel-redirect URI prefix: #{prefix.inspect}"
      end

      if prefix == '/'
        prefix
      elsif prefix.split('/').drop(1).any? { |segment| traversal_segment?(segment) }
        raise ArgumentError, "invalid x-accel-redirect URI prefix: #{prefix.inspect}"
      else
        prefix.chomp('/') + '/'
      end
    end

    def traversal_segment?(segment)
      decoded_dots = segment.gsub(/%2e/i, '.')
      decoded_dots == '.' || decoded_dots == '..'
    end

    def strict_accel_path(body)
      path = ::File.realpath(body.to_path)
      return nil unless ::File.file?(path)

      root, prefix = @strict_mappings
        .select { |directory, _| path_within?(directory, path) }
        .max_by { |directory, _| directory.bytesize }

      return nil unless root

      relative_path = if root == ::File::SEPARATOR
        path.byteslice(1, path.bytesize - 1)
      else
        path.delete_prefix(root + ::File::SEPARATOR)
      end

      url = prefix + ::Rack::Utils.escape_path(relative_path).gsub('?', '%3F')

      if url.match?(/[\r\n]/)
        raise ArgumentError, "x-accel-redirect header must not contain a newline"
      end

      url
    rescue SystemCallError, ArgumentError, TypeError
      nil
    end

    def path_within?(directory, path)
      directory == ::File::SEPARATOR ||
        path == directory ||
        path.start_with?(directory + ::File::SEPARATOR)
    end

    def replace_with_sendfile(response, headers, body, type, url)
      headers[CONTENT_LENGTH] = '0'
      headers[type.downcase] = url
      original_body = body
      response[2] = Rack::BodyProxy.new([]) do
        original_body.close if original_body.respond_to?(:close)
      end
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
