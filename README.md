# Rack CORS Middleware [![Build Status](https://github.com/cyu/rack-cors/actions/workflows/ci.yaml/badge.svg)](https://github.com/cyu/rack-cors/actions)

`Rack::Cors` provides support for Cross-Origin Resource Sharing (CORS) for Rack compatible web applications.

The [CORS spec](http://www.w3.org/TR/cors/) allows web applications to make cross domain AJAX calls without using workarounds such as JSONP. See [further explanations on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

## Installation

Install the gem:

`gem install rack-cors`

Or in your Gemfile:

```ruby
gem 'rack-cors'
```


## Configuration

### Rails Configuration
For Rails, you'll need to add this middleware on application startup. A practical way to do this is with an initializer file. For example, the following will allow GET, POST, PATCH, or PUT requests from any origin on any resource:

```ruby
# config/initializers/cors.rb

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins '*'
    resource '*', headers: :any, methods: [:get, :post, :patch, :put]
  end
end
```

NOTE: If you create application with `--api` option, configuration is automatically generated in `config/initializers/cors.rb`.

We use `insert_before` to make sure `Rack::Cors` runs at the beginning of the stack to make sure it isn't interfered with by other middleware (see `Rack::Cache` note in **Common Gotchas** section). Basic setup examples for Rails 5 & Rails 6 can be found in the examples/ directory.

See The [Rails Guide to Rack](http://guides.rubyonrails.org/rails_on_rack.html) for more details on rack middlewares or watch the [railscast](http://railscasts.com/episodes/151-rack-middleware).

Read more about it here in the [Rails Guides](https://guides.rubyonrails.org/configuring.html#configuring-middleware)

### Rack Configuration

NOTE: If you're running Rails, adding `config/initializers/cors.rb` should be enough.  There is no need to update `config.ru` as well.

In `config.ru`, configure `Rack::Cors` by passing a block to the `use` command:

```ruby
use Rack::Cors do
  allow do
    origins 'localhost:3000', '127.0.0.1:3000',
            /\Ahttp:\/\/192\.168\.0\.\d{1,3}(:\d+)?\z/
            # regular expressions can be used here

    resource '/file/list_all/', :headers => 'x-domain-token'
    resource '/file/at/*',
        methods: [:get, :post, :delete, :put, :patch, :options, :head],
        headers: 'x-domain-token',
        expose: ['Some-Custom-Response-Header'],
        max_age: 600
        # headers to expose
  end

  allow do
    origins '*'
    resource '/public/*', headers: :any, methods: :get

    # Only allow a request for a specific host
    resource '/api/v1/*',
        headers: :any,
        methods: :get,
        if: proc { |env| env['HTTP_HOST'] == 'api.example.com' }
  end
end
```

### Configuration Reference

#### Middleware Options
* **debug** (boolean):  Enables debug logging and `X-Rack-CORS` HTTP headers for debugging.
* **logger** (Object or Proc): Specify the logger to log to.  If a proc is provided, it will be called when a logger is needed.  This is helpful in cases where the logger is initialized after `Rack::Cors` is initially configured, like `Rails.logger`.

#### Origin
Origins can be specified as a string, a regular expression, or as '\*' to allow all origins.

**\*SECURITY NOTE:** Be careful when using regular expressions to not accidentally be too inclusive.  For example, the expression `/https:\/\/example\.com/` will match the domain *example.com.randomdomainname.co.uk*.  It is recommended that any regular expression be enclosed with start & end string anchors, like `\Ahttps:\/\/example\.com\z`.

Additionally, origins can be specified dynamically via a block of the following form:
```ruby
  origins { |source, env| true || false }
```

A Resource path can be specified as exact string match (`/path/to/file.txt`) or with a '\*' wildcard (`/all/files/in/*`).  A resource can take the following options:

* **methods** (string or array or `:any`): The HTTP methods allowed for the resource.
* **headers** (string or array or `:any`): The HTTP headers that will be allowed in the CORS resource request.  Use `:any` to allow for any headers in the actual request.
* **expose** (string or array): The HTTP headers in the resource response can be exposed to the client.
* **credentials** (boolean, default: `false`): Sets the `Access-Control-Allow-Credentials` response header. **Note:** If a wildcard (`*`) origin is specified, this option cannot be set to `true`.  Read this [security article](http://web-in-security.blogspot.de/2017/07/cors-misconfigurations-on-large-scale.html) for more information.
* **max_age** (number): Sets the `Access-Control-Max-Age` response header.
* **if** (Proc): If the result of the proc is true, will process the request as a valid CORS request.
* **vary** (string or array): A list of HTTP headers to add to the 'Vary' header.

### Combining Overlapping Resources

When several `allow` blocks (or several `resource` entries) cover the same path, `Rack::Cors` can combine them in one of two ways, selected with the middleware-level `combine` option:

* **`:first_match`** (default): the first resource matching the request is used, exactly as in previous versions.
* **`:intersect`**: every resource matching the request must permit it. Their permissions are intersected.

```ruby
use Rack::Cors, combine: :intersect do
  # Broad rule: the whole /api namespace allows GET and POST from any origin.
  allow do
    origins '*'
    resource '/api/*', methods: [:get, :post], headers: :any, max_age: 600
  end

  # Narrow rule: the admin section additionally only allows GET and a
  # specific header.  Requests to /api/admin/* must satisfy both rules.
  allow do
    origins 'https://trusted.example'
    resource '/api/admin/*', methods: [:get], headers: 'X-Admin'
  end
end
```

Combination rules used by `:intersect`:

* **origins**: the request origin must be permitted by *every* `allow` block that covers the path. If all covering blocks use wildcard origins, the response uses `*`; otherwise the specific origin is echoed.
* **methods**: the intersection of the configured method sets. `:any` stands for the full method set; an unconfigured `methods` option means `[:get]` (these three cases are never conflated). If the intersection is empty, the request is denied (`deny-method`).
* **headers**: the intersection of the configured header lists. `:any` stands for any header; an unconfigured (or empty) list only allows the CORS simple headers. CORS simple headers are always allowed.
* **credentials**: `true` only when *every* matched rule sets `credentials: true`.
* **expose**: the union of the matched rules' `expose` lists; unconfigured rules contribute nothing.
* **max_age**: the minimum of the matched rules' explicitly configured values; `7200` is used when no rule configures it (the default is not mixed into a configured minimum).

Contradictions that can be detected without a request (e.g. two unconditional resources on the same literal path with disjoint method lists, or `allow` blocks with disjoint literal origin lists) raise `Rack::Cors::Resource::CorsMisconfigurationError` when the middleware initializes. Decisions that depend on the request — origins declared as regular expressions or Procs, and `:if` blocks — are evaluated for each request, so an empty intersection discovered there denies the request instead.

Intersection is computed from the set of matching rules, not from their order: declaring the broad and narrow rules in either order gives identical responses.


## Common Gotchas

### Origin Matching

* When specifying an origin, make sure that it does not have a trailing slash.

* When specifying an HTTP origin that uses the scheme's default port (e.g. `http://example.test:80`), some clients may not strip the port which could result in unexpected blocked requests (additional context [here](https://github.com/request/request/pull/2904)).

### Testing Postman and/or cURL

* Make sure you're passing in an `Origin:` header.  That header is required to trigger a CORS response.  Here's [a good SO post](https://stackoverflow.com/questions/12173990/how-can-you-debug-a-cors-request-with-curl) about using cURL for testing CORS.
* Make sure your origin does not have a trailing slash.

### Positioning in the Middleware Stack

Positioning of `Rack::Cors` in the middleware stack is very important. In the Rails example above we put it above all other middleware which, in our experience, provides the most consistent results.

Here are some scenarios where incorrect positioning have created issues:

* **Serving static files.**  Insert before `ActionDispatch::Static` so that static files are served with the proper CORS headers.  **NOTE:** this might not work in production as static files are usually served from the web server (Nginx, Apache) and not the Rails container.

* **Caching in the middleware.**  Insert before `Rack::Cache` so that the proper CORS headers are written and not cached ones.

* **Authentication via Warden**  Warden will return immediately if a resource that requires authentication is accessed without authentication.  If `Warden::Manager`is in the stack before `Rack::Cors`, it will return without the correct CORS headers being applied, resulting in a failed CORS request.

You can run the following command to see what the middleware stack looks like:

```bash
bundle exec rails middleware
```

Note that the middleware stack is different in production.  For example, the `ActionDispatch::Static` middleware will not be part of the stack if `config.serve_static_assets = false`.  You can run this to see what your middleware stack looks like in production:

```bash
RAILS_ENV=production bundle exec rails middleware
```

### Serving static files

If you trying to serve CORS headers on static assets (like CSS, JS, Font files), keep in mind that static files are usually served directly from web servers and never runs through the Rails container (including the middleware stack where `Rack::Cors` resides).

In Heroku, you can serve static assets through the Rails container by setting `config.serve_static_assets = true` in `production.rb`.

### Custom Protocols (chrome-extension://, ionic://, etc.)

Prior to 2.0.0, `http://`, `https://`, and `file://` are the only protocols supported in the `origins` list. If you wish to specify an origin that
has a custom protocol (`chrome-extension://`, `ionic://`, etc.) simply exclude the protocol. [See issue.](https://github.com/cyu/rack-cors/issues/100)

For example, instead of specifying `chrome-extension://aomjjhallfgjeglblehebfpbcfeobpga` specify `aomjjhallfgjeglblehebfpbcfeobpga` in `origins`.

As of 2.0.0 (currently in RC1), you can specify origins with a custom protocol.

### Rails 6 Host Matching

Rails 6 will block requests from unauthorized hosts, and this issue can be confused as a CORS related error. So in development, if you're making requests using something other than localhost or 127.0.0.1, make sure the server host has been authorized. [More info here](https://guides.rubyonrails.org/configuring.html#actiondispatch-hostauthorization)
