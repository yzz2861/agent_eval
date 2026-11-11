# Guide

This will guide you through the basic features of `pwdlib`.

## Password hashing

To manage password hashes, `pwdlib` exposes the [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) class. The difference with a "plain" hash algorithm helper is that it supports **multiple algorithms**. Why it's useful?

Currently, the safest and recommended algorithm for password hashing is [Argon2](https://en.wikipedia.org/wiki/Argon2). But it's probable that in the coming years, a new and even safer algorithm emerges. Thanks to a wrapper like [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash), we'll be able to verify hash generated with the older algorithm while upgrading them to the newer one.

This is how you create an instance of [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) with Argon2 and Bcrypt support:

```py
from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

password_hash = PasswordHash((
    Argon2Hasher(),
    BcryptHasher(),
))
```

[`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) expects a tuple (or list) of hashing algorithms.

!!! warning "The corresponding dependencies must be installed"

    Hashing algorithms are available through third-party implementations. Therefore, you should install the extra for all the algorithms you want to use.

    **For Argon2**

    ```sh
    pip install 'pwdlib[argon2]'
    ```

    **For Bcrypt**

    ```sh
    pip install 'pwdlib[bcrypt]'
    ```

    **Both!**

    ```sh
    pip install 'pwdlib[argon2,bcrypt]'
    ```

The **first** algorithm in the list is considered the **current algorithm**. New and updated hashes will use this algorithm.

!!! tip "I don't know what to choose!"

    If you start a new application, you can instantiate [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) using the [`recommended`](./reference/pwdlib.md#pwdlib.PasswordHash.recommended) class method. It'll use the Argon2 algorithm under the hood.

    ```py
    password_hash = PasswordHash.recommended()
    ```

### Hash a password

Once you have a [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) instance, you can [`hash`](./reference/pwdlib.md#pwdlib.PasswordHash.hash) a user's password:

```py
hash = password_hash.hash("herminetincture")
```

The resulting string is a hash generated from the **current algorithm**, which you can safely store in your database.

!!! question "Where is the salt?"

    If you know about password hashing algorithms, you probably know that *salting* the password is an important security feature. Back in the days, it was common to store the salt separately from the hash. Nowadays, most algorithms have a specific structure allowing them to store algorithm parameters and salt along with the hash in one string.

    For example, here is an Argon2 hash:

    ```
    $argon2id$v=19$m=65536,t=3,p=4$ugY9gvgMUycvF7hrnoi8oQ$uqcZOh96YysaG+s3A+RcZIccgaiQsynxfBlqUNxeRT4
    ```

### Verify a password

When you want to verify a password corresponds to a hash, use the [`verify`](./reference/pwdlib.md#pwdlib.PasswordHash.verify) method:

```py
valid = password_hash.verify("herminetincture", hash)
```

Under the hood, it'll check against all the enabled algorithms. It means that if older users still have a hash with a legacy algorithm, we'll still be able to verify it.

The resulting boolean indicates you if the hash corresponds to this password or not.

However, in most cases, you probably want to use the method we describe below.

### Verify and update a password

As we said, [`verify`](./reference/pwdlib.md#pwdlib.PasswordHash.verify) checks the hash against all the enabled algorithms. However, it's generally a good idea to take this chance to update the hash to the more secure current algorithm.

This is the purpose of the [`verify_and_update`](./reference/pwdlib.md#pwdlib.PasswordHash.verify_and_update) method: it verifies the password against a hash and, if it's valid and using an outdated algorithm, will hash it again using the current algorithm.


```py
valid, updated_hash = password_hash.verify_and_update("herminetincture", hash)
```

If the hash needs to be updated, `updated_hash` will be a string. Otherwise, it's `None`. Then, don't forget to update it in your database.

It's worth to note that the hash is also upgraded if the **settings of the algorithm** has been changed, like the time or memory cost.

## Adding a pepper with key rotation

A pepper is a server-side secret combined with the password before the regular hashing step. It adds protection in case the password database leaks on its own. `pwdlib` keeps peppering **opt-in**: instances created without a pepper produce exactly the same hashes as before.

Enable it by passing a [`PepperStrategy`](./reference/pwdlib.hashers.md#pwdlib.hashers.base.PepperStrategy) to [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash):

```py
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.base import PepperStrategy

pepper = PepperStrategy(
    current_key_id="key-2",
    keys={
        "key-1": previous_pepper_secret,  # kept during the rotation window
        "key-2": current_pepper_secret,
    },
)
password_hash = PasswordHash((Argon2Hasher(),), pepper=pepper)
```

The password is first derived through HMAC-SHA-256 keyed by the pepper, then the digest goes through the regular hasher. The stored value only embeds the non-secret key identifier:

```
$pwdlib-pepper$v1$key-2$argon2id$v=19$m=65536,t=3,p=4$...
```

The key material itself is never part of the hash. During a rotation window, hashes stamped with the previous key id are still verified with the previous key, while new and upgraded hashes use `current_key_id`.

### Rotation window and retirement

Rolling a key is a configuration change, not a data migration:

1. Add the new key to `keys` and point `current_key_id` at it.
2. Let users log in. [`verify_and_update`](./reference/pwdlib.md#pwdlib.PasswordHash.verify_and_update) verifies old records with the previous key and returns a fresh hash using the current key.
3. Once every active record has been upgraded, retire the old key by setting its material to `None`, then remove the id entirely.

Failure reasons stay distinct so monitoring never confuses a missing key with a wrong password:

- `UnknownPepperKeyError`: the wrapper references a key id that is not registered.
- `MissingPepperKeyError`: the key id is registered but its secret material was retired (`None`).
- `CorruptPepperHashError`: the wrapper itself is structurally invalid.
- A wrong password still returns `False` from `verify`.

Error messages, logs and exception representations only contain the non-secret key id, never the pepper material or the original hash.

Legacy records stored without a pepper keep verifying unchanged: a successful `verify_and_update` upgrades them to a peppered hash on the next login.
