module.exports = {
  'security:formatUserForSerialization': 'cleanUserCredentials',
  'auth:beforeUpdateSelf': 'encryptCredentials',
  'admin:beforeCreateFirstAdmin': 'encryptCredentials',
  'security:beforeCreateFirstAdmin': 'encryptCredentials',
  'security:beforeCreateUser': 'encryptCredentials',
  'security:beforeUpdateUser': 'encryptCredentials',
  'security:beforeCreateOrReplaceUser': 'encryptCredentials',
  'security:beforeCreateRestrictedUser': 'encryptCredentials'
};
