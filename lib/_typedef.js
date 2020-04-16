/**
 * @typedef {{
 *  users?: Array<string>
 *  profiles?: Array<string>
 *  roles?: Array<string>
 * }} PasswordPolicyAppliesTo
 */

/**
 * @typedef {{
 *  expiresAfter?: string
 *  forbidReusedPasswordCount?: Number
 *  mustChangePasswordIfSetByAdmin?: boolean
 *  passwordRegex: string
 *  appliesTo: PasswordPolicyAppliesTo
 * }} PasswordPolicy
 */

/**
 * @typedef {{
 *  algorithm: 'RSA-SHA1'|'RSA-SHA224'|'RSA-SHA256'|'RSA-SHA384'|'RSA-SHA512'|'sha1'|'sha1WithRSAEncryption'|'sha224'|'sha224WithRSAEncryption'|'sha256'|'sha256WithRSAEncryption'|'sha384'|'sha384WithRSAEncryption'|'sha512'|'sha512WithRSAEncryption'
 *  stretching: boolean,
 *  digest: string,
 *  encryption: 'argon2'|'argon2i'|'argon2d'|'argon2id'|'bcrypt'|'hash'|'hmac'|'scrypt',
 *  passwordPolicies: Array<PasswordPolicy>,
 *  resetPasswordExpiresIn?: string|Number
 *  requirePassword: boolean
 * }} AuthLocalPluginConfig
 */

/**
 * @typedef {{
 *  userPassword: string
 *  userSalt: string
 *  algorithm: string
 *  stretching: string
 *  pepper: boolean
 *  encryption: string
 *  archivedAt: Date
 *  updatedAt: Date
 * }} Password
 */

/**
 * @typedef {{
 *  kuid: string
 *  userPassword: string
 *  userSalt: string
 *  algorithm: string
 *  stretching: boolean
 *  passwordHistory: Array<Password>
 *  pepper: boolean
 *  encryption: string
 * }} UserDocument
 */

/**
 * @typedef {{
 *  _id: string
 *  profileIds: Array<string>
 * }} KuzzleUser
 */

/**
 * @typedef {{
 *  _id: string
 *  policies: Array<KuzzleUserProfilePolicy>
 *  rateLimit: integer
 * }} KuzzleUserProfile
 */

/**
 * @typedef {{
 *  restrictedTo: Array<{{
 *    index: string
 *    collections?: Array<string>
 *  }}>
 *  roleId: string
 * }} KuzzleUserProfilePolicy
 */