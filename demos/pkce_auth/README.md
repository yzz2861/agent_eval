# Local OAuth 2.0 PKCE demo

This demo runs entirely on localhost and includes a fake authorization server.
It demonstrates the complete authorization-code flow with S256 PKCE,
one-time state validation, initiator-bound state cookies, and atomic state
consumption.

Run it with:

```sh
python main.py
```

Then open:

- http://localhost:8888/ — start a successful login.
- http://localhost:8888/login?deny=1 — simulate provider rejection.

The code verifier is kept only in server-side login state. Neither the fake
provider pages, the application logs, nor error responses print the verifier
or issued access token.
