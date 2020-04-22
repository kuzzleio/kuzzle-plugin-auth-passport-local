const ms = require('ms');

/**
 * @param {AuthenticationPlugin} plugin
 * @returns {User}
 */
module.exports = plugin => {
  // private properties need to be hidden from serialization
  const _kuzzleUser = Symbol.for('_kuzzleUser');
  const _kuzzleUserProfiles = Symbol.for('_kuzzleUserProfilesa');

  /**
   * @class User
   * @property {string} _id
   * @property {string} algorithm
   * @property {string} encryption
   * @property {string} kuid
   * @property {Array<Password>} passwordHistory
   * @property {boolean} pepper
   * @property {string} stretching
   * @property {string} userPassword
   * @property {string} userSalt
   * @property {string} updater
   * @property {{
   *   author: null,
   *   createdAt: number,
   *   updatedAt: number,
   *   updater: null
   * }} _kuzzle_info
   */
  class User {
    /**
     * @param {UserDocument} document
     */
    constructor(document) {
      this.algorithm = plugin.config.algorithm;
      this.encryption = plugin.config.encryption;
      this.passwordHistory = [];
      this.stretching = plugin.config.stretching;

      if (document) {
        this._id = document._id;
        this.algorithm = document.algorithm;
        this.encryption = document.encryption;
        this.kuid = document.kuid;
        this.passwordHistory = document.passwordHistory || [];
        this.pepper = document.pepper;
        this.stretching = document.stretching;
        this.userPassword = document.userPassword;
        this.userSalt = document.userSalt;
        this._kuzzle_info = document._kuzzle_info;
      }
    }

    /**
     * @returns {Promise<null|KuzzleUser>}
     */
    async getKuzzleUser() {
      if (!this.kuid) {
        return null;
      }

      if (!this[_kuzzleUser]) {
        try {
          this[_kuzzleUser] = await plugin.context.accessors.sdk.security.getUser(this.kuid);
        }
        catch (e) {
          if (e.id === 'services.storage.not_found') {
            this[_kuzzleUser] = null;
          }
          else {
            throw e;
          }
        }
      }

      return this[_kuzzleUser];
    }

    /**
     * @returns {Promise<Array<KuzzleUserProfile>>}
     */
    async getKuzzleUserProfiles() {
      if (!this.kuid) {
        return [];
      }

      if (!this[_kuzzleUserProfiles]) {
        const kuzzleUser = await this.getKuzzleUser();
        if (kuzzleUser === null) {
          return [];
        }

        this[_kuzzleUserProfiles] = await plugin.context.accessors.sdk.security.mGetProfiles(
          kuzzleUser.content.profileIds
        );
      }
      return this[_kuzzleUserProfiles];
    }

    /**
     * @returns {Promise<Number>}
     */
    async getPasswordRetention() {
      let retention = 0;

      for (const policy of await this.getPolicies()) {
        if (policy.forbidReusedPasswordCount) {
          retention = Math.max(retention, policy.forbidReusedPasswordCount);
        }
      }

      return retention;
    }

    /**
     * @returns {Promise<Array<PasswordPolicy>>}
     */
    async getPolicies() {
      if (!this.kuid) {
        return [];
      }

      const policies = [];

      for (const policy of plugin.config.passwordPolicies) {
        if (policy.appliesTo === '*') {
          policies.push(policy);
        }

        if (policy.appliesTo.users && policy.appliesTo.users.includes(this.kuid)) {
          policies.push(policy);
        }

        const kuzzleUser = await this.getKuzzleUser();
        if (kuzzleUser === null) {
          continue;
        }

        if (policy.appliesTo.profiles) {
          for (const kuzzleUserProfile of await this.getKuzzleUserProfiles()) {
            if (policy.appliesTo.profiles.includes(kuzzleUserProfile._id)) {
              policies.push(policy);
            }
          }
        }

        if (policy.appliesTo.roles) {
          for (const profile of await this.getKuzzleUserProfiles()) {
            for (const {roleId} of profile.policies) {
              if (policy.appliesTo.roles.includes(roleId)) {
                policies.push(policy);
              }
            }
          }
        }
      }

      return policies;
    }

    /**
     * @returns {Promise<boolean>}
     */
    async isPasswordExpired() {
      for (const policy of await this.getPolicies()) {
        if (policy.expiresAfter
          && Date.now() > (this._kuzzle_info.updatedAt || this._kuzzle_info.createdAt) + ms(policy.expiresAfter)
        ) {
          return true;
        }
      }

      return false;
    }

    /**
     * @returns {Promise<boolean>}
     */
    async passwordMustBeChanged () {
      for (const profile of await this.getKuzzleUserProfiles()) {
        for (const policy of profile.policies) {
          if (policy.roleId === 'admin') {
            // admin users are not impacted
            return false;
          }
        }
      }

      for (const policy of await this.getPolicies()) {
        if (policy.mustChangePasswordIfSetByAdmin
          && this.updater !== this.kuid
        ) {
          return true;
        }
      }

      return false;
    }

    /**
     * @param {{ username: string, password: string }} credentials
     * @returns {Promise<boolean>}
     */
    async validateCredentials(credentials) {
      for (const policy of await this.getPolicies()) {
        // forbid login in password
        if (policy.forbidLoginInPassword
          && credentials.password
          && (credentials.username || this._id)
          && credentials.password.toLowerCase().indexOf((credentials.username || this._id).toLowerCase()) > -1
        ) {
          plugin.context.errorsManager.throw('login-in-pasword');
        }

        // password regex
        if (policy.passwordRegex && credentials.password) {
          const matches = policy.passwordRegex.match(/^\/(?<pattern>.*?)\/(?<flags>[gismuy]+)/);
          const regex = matches
            ? new RegExp(matches.groups.pattern.replace(/\\\//g, '/'), matches.groups.flags)
            : new RegExp(policy.passwordRegex);

          if (!regex.test(credentials.password)) {
            plugin.context.errorsManager.throw('weak-password');
          }
        }

        if (policy.forbidReusedPasswordCount > 0
          && credentials.password
        ) {
          const passwords = [...this.passwordHistory];

          if (this.userPassword) {
            // is not set on user create
            /* @type Password */
            const current = {
              userPassword: this.userPassword,
              userSalt: this.userSalt,
              algorithm: this.algorithm,
              stretching: this.stretching,
              pepper: this.pepper,
              encryption: this.encryption,
              archivedAt: Date.now(),
              updatedAt: this._kuzzle_info.updatedAt
            };
            passwords.unshift(current);
          }

          for (let i = 0; i < Math.min(policy.forbidReusedPasswordCount, passwords.length); i++) {
            if (passwords[i].userPassword === await plugin.passwordManager.encryptPassword(
              credentials.password,
              passwords[i].userSalt,
              passwords[i].algorithm,
              passwords[i].stretching,
              passwords[i].encryption
            )) {
              plugin.context.errorsManager.throw('reused-password');
            }
          }
        }
      }

      return true;
    }
  }

  return User;
};
