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
  "requirePassword": false,
  "passwordPolicies": []
}
```

## General settings

* `algorithm`: one of the supported encryption algorithms (run [crypto.getHashes()](https://nodejs.org/dist/latest-v10.x/docs/api/crypto.html#crypto_crypto_gethashes) to get the complete list). Examples: `sha256`, `sha512`, `blake2b512`, `whirlpool`, ...
* `stretching` must be a boolean and controls if the password is stretched or not.
* `digest` describes how the hashed password is stored in the persisting layer. See other possible values in the [node.js documentation](https://nodejs.org/api/buffer.html#buffer_buf_tostring_encoding_start_end)
* `encryption` determines whether the hashing algorithm uses `crypto.createHash` (`hash`) or `crypto.createHmac` (`hmac`). For more details, see the [node.js documentation](https://nodejs.org/api/crypto.html)
* `requirePassword` must be a boolean. If true, this makes this plugin refuse any credentials update or deletion, unless the currently valid password is provided or the change is performed via the `security` controller
* `resetPasswordExpiresIn`: A positive time representation of the delay after which a reset password token expires (see [ms](https://www.npmjs.com/package/ms) for possible formats). Users with expired passwords are given a `resetPasswordToken` when logging in and must change their password to be allowed to log in again.

## Password policies

Password policies can be used to define a set of additional rules to apply to users or groups of users.

Each password policy is an object with the following properties:

* `appliesTo`: (mandatory). Can be either set to the `*` to match all users, or an object.
* `appliesTo.users`: An array of user `kuids` the policy applies to.
* `appliesTo.profiles`: An array of `profile` ids the policy applies to.
* `appliesTod.roles`: An array of `role` ids the policy applies to.

> Either `users`, `profiles` or `roles` must be set if `appliesTo` is an object.

### Optional properties

* `expiresAfter`: A positive time representation of the delay after which a password expires (see [ms](https://www.npmjs.com/package/ms) for possible formats). Users with expired passwords are given a `resetPasswordToken` when login in and must change their password to be allowed to log in again.
* `forbidLoginInPassword`: If set to `true`, prevent users to use their username in part of the password. The check is case-**in**sensitive.
* `forbidReusedPasswordCount`: The number of passwords to store in history and check against when a new password is set.
* `mustChangePasswordIfSetByAdmin`: If set to `true`, when the password is set for a user by someone else, the user will receive a `resetPasswordToken` upon next login and will have to change her password before being allowed to log in again.
* `passwordRegex`: A string representation of a regular expression to test on new passwords.

### Examples

```json
{
  "passwordPolicies": [
    {
      "appliesTo": "*",
      "forbidLoginPassword": true,
      "passwordRegex": ".{6,}"
    },
    {
      "appliesTo": {
        "profiles": ["editor"],
        "roles": ["admin"]
      },
      "expiresAfter": "30d",
      "mustChangePasswordIfSetByAdmin": true,
      "passwordRegex": "(?=.*[a-zA-Z])(?=.*[0-9])(?=.{8,}}"
    },
    {
      "appliesTo": {
        "roles": ["admin"]
      },
      "passwordRegex": "((?=.*[a-z](?=.*[A-Z])(?=.*[0-9])(?=.*\\W)(?=.{8,}})|(?=.{24,})"
    }
  ]
}
```

In the example above, no user can use a password that includes the login and the password must be at least 6 chars long.

Editors and admin users passwords expire every 30 days and the password must be at least 8 chars long and include at least one letter and one digit.

Admin users passwords must either be 24 or more chars long, or include a lower case char, an upper case char, a digit and a special char.


# Usage

## Login

To log in using Kuzzle's API:

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

## requirePassword option

By default, there is no restriction to update or delete credentials (provided the current user is logged in).

However, if the option `requirePassword` is set to true, this plugin will refuse to update credentials unless either the currently valid password is also provided, or the change is performed via the `security` controller.

To provide the password parameter, add it at the root level of the provided JSON payload.

Example:

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
  }
}
```

## Reset Password

### Permissions

By default, all routes are denied to non-admin users. You will need to allow them if needed. A typical setup may look like:

_.kuzzlerc_
```json
{
  "security": {
    "roles": {
      "anonymous": {
        "controllers": {
          "auth": {
            "actions": {
              "checkToken": true,
              "getCurrentUser": true,
              "getMyRights": true,
              "login": true
            }
          },
          "kuzzle-plugin-auth-passport-local/password": {
            "actions": {
              "reset": true
            }
          },
          "server": {
            "actions": {
              "publicApi": true
            }
          }
        }
      }
    }
  }
}
```

See [Kuzzle user authentication documentation](https://docs.kuzzle.io/core/2/guides/essentials/user-authentication/) for more details about Kuzzle authentication mechanism.

### Reset password

```json
{
  "controller": "kuzzle-plugin-auth-passport-local/password",
  "action": "reset",
  "body": {
    "password": "new password",
    "token": "<reset password>"
  }
}
```

For HTTP:

```shell
curl \
    -XPOST \
    -H "Content-type: application/json" \
    -d '{"password": "new password", "token": "<reset token>"}' \
    kuzzle/_plugin/kuzzle-plugin-auth-passport-local/password/reset
```

Response:

```json
{
  "requestId": "8a3c1366-e9cc-4e4e-8fe8-8e90f79d02a5",
  "status": 200,
  "error": null,
  "controller": "kuzzle-plugin-auth-passport-local/password",
  "action": "reset",
  "collection": null,
  "index": null,
  "volatile": null,
  "result": {
    "_id": "user",
    "expiresAt": 1587466666298,
    "jwt": "<login token>",
    "ttl": 3600000
  }
}
```

The returned jwt can be used the same way as if the user had logged in.

### Get a reset password token

A reset token is automatically returned upon login if the password is either expired or must be changed according to the defined policies.

Another way to get a reset token for a user is to use the `getResetPasswordToken` route. 
For instance, it can be used programatically from a plugin to generate a reset password link for a user in case he lost his password.

> :warning: **This route MUST be secured and accessible to permitted users only!**

```json
{
  "controller": "kuzzle-plugin-auth-passport-local/password",
  "action": "getResetPasswordToken",
  "_id": "<kuid>"
}
```

For HTTP

```
curl kuzzle/_plugin/kuzzle-plugin-auth-passport-local/password/resetToken/<kuid>
```

Response:
```json
{
  "requestId": "7a701827-98eb-4122-8691-8f27d9c77fef",
  "status": 200,
  "error": null,
  "controller": "kuzzle-plugin-auth-passport-local/password",
  "action": "getResetPasswordToken",
  "collection": null,
  "index": null,
  "volatile": null,
  "result": {
    "resetToken": "<reset password token>"
  }
}
```

# How to create a plugin

See [Kuzzle plugin documentation](https://docs.kuzzle.io/core/2/plugins/) about plugin for more information about how to create your own plugin.

# About Kuzzle

For UI and IoT developers, [Kuzzle](https://github.com/kuzzleio/kuzzle) is an open-source solution that handles all the data management
(CRUD, real-time storage, search, high-level features, etc).

[Kuzzle](https://github.com/kuzzleio/kuzzle) features are accessible through a secured API. It can be used through a large choice of protocols such as HTTP, Websocket or MQTT.
