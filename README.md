# py_webauthn
[![PyPI](https://img.shields.io/pypi/v/webauthn.svg)](https://pypi.python.org/pypi/webauthn) [![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/duo-labs/py_webauthn/master/LICENSE) ![Pythonic WebAuthn](https://img.shields.io/badge/Pythonic-WebAuthn-brightgreen?logo=python&logoColor=white)

A Python3 implementation of the server-side of the [WebAuthn API](https://www.w3.org/TR/webauthn-2/) focused on making it easy to leverage the power of WebAuthn.

This library supports all FIDO2-compliant authenticators, including security keys, Touch ID, Face ID, Windows Hello, Android biometrics...and pretty much everything else.

## Installation

This module is available on **PyPI**:

`pip install webauthn`

## Requirements

- Python 3.10 and up

## Usage

The library exposes just a few core methods on the root `webauthn` module:

- `generate_registration_options()`
- `verify_registration_response()`
- `generate_authentication_options()`
- `verify_authentication_response()`

Two additional helper methods are also exposed:

- `options_to_json()`
- `base64url_to_bytes()`

Additional data structures are available on `webauthn.helpers.structs`. These dataclasses are useful for constructing inputs to the methods above, and for providing type hinting to help ensure consistency in the shape of data being passed around.

Generally, the library makes the following assumptions about how a Relying Party implementing this library will interface with a webpage that will handle calling the WebAuthn API:

- JSON is the preferred data type for transmitting registration and authentication options from the server to the webpage to feed to `navigator.credentials.create()` and `navigator.credentials.get()` respectively.
- JSON is the preferred data type for transmitting WebAuthn responses from the browser to the server.
- Bytes are not directly transmittable in either direction as JSON, and so should be encoded to and decoded from [base64url to avoid introducing any more dependencies than those that are specified in the WebAuthn spec](https://www.w3.org/TR/webauthn-2/#sctn-dependencies).
  - See the [`WebAuthnBaseModel` struct](https://github.com/duo-labs/py_webauthn/blob/master/webauthn/helpers/structs.py#L13) for more information on how this is achieved

The examples mentioned below include uses of the `options_to_json()` helper (see above) to show how easily `bytes` values in registration and authentication options can be encoded to base64url for transmission to the front end.

The examples also include demonstrations of how to pass JSON-ified responses, using base64url encoding for `ArrayBuffer` values, into `parse_registration_credential_json` and `parse_authentication_credential_json` to be automatically parsed by the methods in this library. An RP can pair this with corresponding custom front end logic, or one of several frontend-specific libraries (like [@simplewebauthn/browser](https://www.npmjs.com/package/@simplewebauthn/browser), for example) to handle encoding and decoding such values to and from JSON.

Other arguments into this library's methods that are defined as `bytes` are intended to be values stored entirely on the server. Such values can more easily exist as `bytes` without needing potentially extraneous encoding and decoding into other formats. Any encoding or decoding of such values in the name of storing them between steps in a WebAuthn ceremony is left up to the RP to achieve in an implementation-specific manner.

### Registration

See **examples/registration.py** for practical examples of using `generate_registration_options()` and `verify_registration_response()`.

You can also run these examples with the following:

```sh
# See "Development" below for venv setup instructions
venv $> uv run -m examples.registration
```

### Authentication

See **examples/authentication.py** for practical examples of using `generate_authentication_options()` and `verify_authentication_response()`.

#### Stateful authentication ceremonies

The stateless `generate_authentication_options()` and `verify_authentication_response()` helpers leave challenge lifecycle management (binding a challenge to a user, marking it consumed, persisting sign counts) entirely to the RP. An RP that only compares a caller-supplied challenge cannot tell whether a challenge was already used, was issued for a different user, or has expired.

`AuthenticationCeremony` is an explicitly enabled, opt-in transactional layer that sits on top of those unchanged helpers:

```python
from webauthn import AuthenticationCeremony
from webauthn.authentication.ceremony import InMemoryAuthenticationChallengeStore, InMemoryCredentialStore

ceremony = AuthenticationCeremony(
    rp_id="example.com",
    expected_origin="https://example.com",
    # Any object implementing the challenge/credential store protocols works;
    # database-backed stores can replace the in-memory reference implementations.
    challenge_store=InMemoryAuthenticationChallengeStore(),
    credential_store=InMemoryCredentialStore(),
)

# Generating options persists a record of the challenge purpose, RP ID,
# allowCredentials, optional userHandle, issuance time and expiry time.
options = ceremony.generate_options(user_handle=user_handle, allow_credentials=descriptors)

# Verification atomically validates the challenge ownership, marks it consumed,
# looks up the credential by credential id, and checks and updates the sign count.
result = ceremony.verify_response(credential)
print(result.user_handle, result.verification.new_sign_count)
```

Guarantees provided by the ceremony layer:

- A challenge is single-use: concurrent submissions of the same challenge have at most one successful consumer, and replays raise `ChallengeAlreadyConsumed`.
- Ownership, purpose, RP ID, expiry, allowCredentials, revocation, backup-flag and sign-count checks run before consumption, so a rejected request never consumes another user's challenge.
- `userHandle` can only confirm the user bound to the challenge; it can never override the binding, including for usernameless ceremonies.
- Legacy authenticators that always report a sign count of zero remain supported; any other non-zero count must strictly increase or the submission is rejected as a replay (`SignCountReplay`).
- Every rejected attempt increments an observable `failed_attempts` counter on the challenge record, keyed by reason.

You can also run these examples with the following:

```sh
# See "Development" below for venv setup instructions
venv $> uv run -m examples.authentication
```

## Development

### Installation

Install uv by following the installation instructions here:

https://docs.astral.sh/uv/getting-started/installation/

Afterwards, run the following command to set up a virtual environment and install the project's
dependencies:

```sh
$> uv sync
```

### Testing

Python's unittest module can be used to execute everything in the **tests/** directory:

```sh
venv $> uv run -m unittest
```

Auto-watching unittests can be achieved with a tool like nodemon.

**All tests:**
```sh
venv $> nodemon --exec "uv run -m unittest" --ext py
```

**An individual test file:**
```sh
venv $> nodemon --exec "uv run -m unittest tests/test_aaguid_to_string.py" --ext py
```

### Linting and Formatting

Linting is handled via `mypy`:

```sh
venv $> uv run -m mypy webauthn
Success: no issues found in 52 source files
```

The entire library is formatted using `black`:

```sh
venv $> uv run -m black webauthn --line-length=99
All done! ✨ 🍰 ✨
52 files left unchanged.
```

## Publishing to PyPI

A GitHub action is defined in [publish.yml](.github/workflows/publish.yml) to publish a new version of [the `webauthn` library on PyPI](https://pypi.org/project/webauthn/) when a Release is created on GitHub:

1. Update [CHANGELOG.md](CHANGELOG.md) with changes for the new release version
2. Increment `__version__` in [webauthn/__init__.py](webauthn/__init__.py) to the same release version
3. Commit the change
4. Create a git tag on the commit above with the same release version
5. Push the tag up to GitHub
6. Go to [Releases > Tags](https://github.com/duo-labs/py_webauthn/tags) and create a release from the new tag
7. Check [Actions > Upload Package to PyPI](https://github.com/duo-labs/py_webauthn/actions/workflows/publish.yml) to confirm a new version of the package made it to PyPI
