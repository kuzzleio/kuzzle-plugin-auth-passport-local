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
        this.algorithm = document.algorithm;
        this.encryption = document.encryption;
        this.kuid = document.kuid;
        this.passwordHistory = document.passwordHistory || [];
        this.pepper = document.pepper;
        this.stretching = document.stretching;
        this.userPassword = document.userPassword;
        this.userSalt = document.userSalt;
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
        this[_kuzzleUser] = await plugin.context.accessors.sdk.security.getUser(this.kuid);
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
          kuzzleUser.profileIds
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

      return plugin.config.passwordPolicies.filter(async policy => {
        if (policy.appliesTo.users && policy.appliesTo.users.includes(this.kuid)) {
          return true;
        }

        const kuzzleUser = await this.getKuzzleUser();
        if (kuzzleUser === null) {
          return false;
        }

        if (policy.appliesTo === '*') {
          return true;
        }

        if (policy.appliesTo.profiles) {
          for (const kuzzleUserProfileId of kuzzleUser.profileIds) {
            if (policy.appliesTo.profiles.includes(kuzzleUserProfileId)) {
              return true;
            }
          }
        }

        if (policy.appliesTo.roles) {
          for (const profile of await this.getKuzzleUserProfiles()) {
            for (const {roleId} of profile.policies) {
              if (policy.appliesTo.roles.includes(roleId)) {
                return true;
              }
            }
          }
        }

        return false;
      });
    }

    /**
     * @returns {Promise<boolean>}
     */
    async isPasswordExpired() {
      for (const policy of await this.getPolicies()) {
        if (policy.expiresAfter
          && Date.now() > this.updatedAt + policy.expiresAfter
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
      for (const policy of await this.getPolicies()) {
        if (policy.mustChangePasswordIfSetByAdmin
          && this.updatedBy !== this.kuid
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
        if (policy.forbidLoginInPassword
          && credentials.password
          && credentials.password.toLowerCase().indexOf(this.kuid.toLowerCase()) > -1
        ) {
          throw new plugin.errors.LoginInPasswordError();
        }

        if (policy.passwordRegex && credentials.password) {
          const matches = policy.passwordRegex.match(/^\/(?<pattern>.*?)\/(?<flags>[gismuy]+)/);
          const regex = matches
            ? new RegExp(matches.pattern.replace(/\\\//g, '/'), matches.flags)
            : new RegExp(policy.passwordRegex);

          if (!regex.test(credentials.password)) {
            throw new plugin.errors.WeakPasswordError();
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
              throw new plugin.errors.ReusedPasswordError();
            }
          }
        }
      }

      return true;
    }
  }

  return User;
};
