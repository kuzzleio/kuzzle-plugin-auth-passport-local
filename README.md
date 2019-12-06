[![Build Status](https://travis-ci.org/kuzzleio/kuzzle-plugin-auth-passport-local.svg?branch=master)](https://travis-ci.org/kuzzleio/kuzzle-plugin-auth-passport-local)

# Plugin Local Password Authentication

This plugin provides a local authentication with username/password with [passportjs module](http://passportjs.org/docs/username-password).

By default, this plugin is already installed in Kuzzle.

## Compatibility matrice

| Kuzzle Version | Plugin Version |
| -------------- | -------------- |
| 1.x.x          | 5.x.x          | 
| 2.x.x          | 6.x.x          | 

# Configuration

The default configuration is as follow:

```json
{
  "algorithm": "sha512",
  "stretching": true,
  "digest": "hex",
  "encryption": "hmac",
  "requirePassword": false
}
```

All the configurations are used to set the behavior of the password hash.

* `algorithm`: one of the supported encryption algorithms (run [crypto.getHashes()](https://nodejs.org/dist/latest-v10.x/docs/api/crypto.html#crypto_crypto_gethashes) to get the complete list). Examples: `sha256`, `sha512`, `blake2b512`, `whirlpool`, ...
* `stretching` must be a boolean and controls if the password is stretched or not.
* `digest` describes how the hashed password is stored in the persisting layer. See other possible values in the [node.js documentation](https://nodejs.org/api/buffer.html#buffer_buf_tostring_encoding_start_end)
* `encryption` determines whether the hashing algorithm uses `crypto.createHash` (`hash`) or `crypto.createHmac` (`hmac`). For more details, see the [node.js documentation](https://nodejs.org/api/crypto.html)
* `requirePassword` must be a boolean. If true, this makes this plugin refuse any credentials update or deletion, unless the currently valid password is provided or the change is performed via the `security` controller

# Usage

This simple plugin associates a password to a custom username.

To login using Kuzzle's API:

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

By default there is no restriction to update or delete credentials (provided the current user is logged in).

However, if the option `requirePassword` is set to true, this plugin will refuse to update credentials unless either the currently valid password is also provided, or the change is performed via the `security` controller.

To provide the password parameter, add it at the root level of the provided JSON payload.

Example (non-HTTP protocol):

```js
{
  "controller": "auth",
  "action": "updateMyCredentials",
  "strategy": "local",
  "jwt": "<currently valid token>",
  "password": "<currently valid password>",
  "body": {
    // just skip the fields you don't want to update
    "username": "<new username>",
    "password": "<new password>"
  },
}
```

Using HTTP, the currently valid password must be put in the querystring:

```
https://kuzzle:7512/credentials/local/_me/_update?password=<currently valid password>
```

See [Kuzzle user authentication documentation](https://docs.kuzzle.io/core/2/guides/essentials/user-authentication/) for more details about Kuzzle authentication mechanism.

# How to create a plugin

See [Kuzzle plugin documentation](https://docs.kuzzle.io/core/2/plugins/) about plugin for more information about how to create your own plugin.

# About Kuzzle

For UI and IoT developers, [Kuzzle](https://github.com/kuzzleio/kuzzle) is an open-source solution that handles all the data management
(CRUD, real-time storage, search, high-level features, etc).

[Kuzzle](https://github.com/kuzzleio/kuzzle) features are accessible through a secured API. It can be used through a large choice of protocols such as HTTP, Websocket or MQTT.
