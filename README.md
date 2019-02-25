[![Build Status](https://travis-ci.org/kuzzleio/kuzzle-plugin-auth-passport-local.svg?branch=master)](https://travis-ci.org/kuzzleio/kuzzle-plugin-auth-passport-local)

# Plugin Local Password Authentication

This plugin provides a local authentication with username/password with [passportjs module](http://passportjs.org/docs/username-password).

By default, this plugin is already installed in Kuzzle.

# Configuration

The default and recommended configuration is:

```json
{
  "algorithm": "sha512",
  "stretching": true,
  "digest": "hex",
  "encryption": "hmac"
}
```

All the configurations are used to set the behavior of the password hash.

* `algorithm`: one of the supported encryption algorithms (run [crypto.getHashes()](https://nodejs.org/dist/latest-v10.x/docs/api/crypto.html#crypto_crypto_gethashes) to get the complete list). Examples: `sha256`, `sha512`, `blake2b512`, `whirlpool`, ...
* `stretching` must be a boolean and controls if the password is stretched or not.
* `digest` describes how the hashed password is stored in the persisting layer. See other possible values in the [node.js documentation](https://nodejs.org/api/buffer.html#buffer_buf_tostring_encoding_start_end)
* `encryption` determines whether the hashing algorithm uses `crypto.createHash` (`hash`) or `crypto.createHmac` (`hmac`). For more details, see the [node.js documentation](https://nodejs.org/api/crypto.html)

# Usage

Just send following data to the **auth** controller:

```json
{
  "controller": "auth",
  "action": "login",
  "strategy": "local",
  "body": {
    "username": "<username>",
    "password": "<password>"
  }
}
```

See [Kuzzle API Documentation](http://docs.kuzzle.io/api-documentation/controller-auth/) for more details about Kuzzle authentication mechanism.

# How to create a plugin

See [Kuzzle documentation](http://docs.kuzzle.io/plugins-reference/) about plugin for more information about how to create your own plugin.

# About Kuzzle

For UI and linked objects developers, [Kuzzle](https://github.com/kuzzleio/kuzzle) is an open-source solution that handles all the data management
(CRUD, real-time storage, search, high-level features, etc).

[Kuzzle](https://github.com/kuzzleio/kuzzle) features are accessible through a secured API. It can be used through a large choice of protocols such as REST, Websocket or Message Queuing protocols.
