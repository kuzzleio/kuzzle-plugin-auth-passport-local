module.exports = function () {
  return {
    // clear password "bar"
    get: kuid => {
      if (kuid === 'ghost') {
        return Promise.resolve(null);
      }

      if (kuid === 'unknownAlgorithm') {
        return Promise.resolve({
          _id: 'bar',
          algorithm: 'can I haz cheezburger?',
          userPassword: 'cheezburger',
          userSalt: 'sugar',
          kuid,
          encryption: 'hmac'
        });
      }

      if (kuid === 'nostretching') {
        return Promise.resolve({
          _id: 'weak',
          algorithm: 'sha1',
          stretching: false,
          userPassword: 'c1d0e06998305903ac76f589bbd6d4b61a670ba6',
          userSalt: 'salt',
          kuid,
          encryption: 'hmac'
        });
      }

      if (kuid === 'withHash') {
        return Promise.resolve({
          _id: 'reallyWeak',
          algorithm: 'sha1',
          stretching: false,
          userPassword: '6318553899daae2941718c02508aeee938af1a1c',
          userSalt: '',
          kuid,
          encryption: 'hash'
        });
      }

      if (kuid === 'withSaltedHash') {
        return Promise.resolve({
          _id: 'mildlyWeak',
          algorithm: 'sha1',
          stretching: false,
          userPassword: '7adea9631925620e692b435c54fecdc5e962416d',
          userSalt: 'salt',
          kuid,
          encryption: 'hash'
        });
      }

      if (kuid === 'withoutEncryption') {
        return Promise.resolve({
          _id: 'foo',
          userPassword: 'ecd4362a92e94f85593580fe02ba4901838e223aa01df2420804b6297c3536afc6db44576d218828397ed1820dfc4988c9fc3aad5a873fd4ec375a4efe56e030e613da409b9c0f73ddfb76645a407a60ef7813da247ce8b8f60737a41103bfdacd5f1e506055005abfafb0f76a1a14ad3b5bfd5b12e034fe1cc1dbc147e3d21014266409bff82f12c38af9057436c3882b5d2b5b86000272036207dbe39103bd927a173d54918dcd807a6292ddd722fb5359e0ccdbbf8b9a828570e517a115ff6e9ce0b5e6e88f05847a98a026224d8f027037ee7fdcb7424140f22e525a7598941271fa2a91328fa651b781a93f0b06c056d01efae7ab6b026882dc85cb86fbcd3c9f3ec4374937d96cbe61cb443e82aa681a25cf274a9dac3c9e8b6a1bc2ae61dcfa6f63ee3900026b384cdf9de188e8aeabcefc60b73662ef5205bd55ccc9b2b7f64d044cfc5d81e6e132889e251c30d1f7babea25014e5bb9d7420c18b7074607d1268d08dc68745ac74acea73ec1fa1737805ebf8f981f2f0bcc0f087110bbdaf387e2e0e50a14e0e696fc4f109fac12f6b32a2c5f065c769ef47ac1488c40e2abd4e21ce4dbb3bc460c004421037c3a6950cd5e1a1c802f8290d7cace2dc9806ec408cf27aff74ca4cfb0cf4ebc8906f18888e0f1e805f294f938ec12aacbbd9071add259431d2ea91563240287e20a4f5c22b247679958230c678be7d',
          userSalt: 'someSalt',
          algorithm: 'sha512',
          stretching: true,
          kuid
        });
      }

      return Promise.resolve({
        _id: 'foo',
        userPassword: 'ecd4362a92e94f85593580fe02ba4901838e223aa01df2420804b6297c3536afc6db44576d218828397ed1820dfc4988c9fc3aad5a873fd4ec375a4efe56e030e613da409b9c0f73ddfb76645a407a60ef7813da247ce8b8f60737a41103bfdacd5f1e506055005abfafb0f76a1a14ad3b5bfd5b12e034fe1cc1dbc147e3d21014266409bff82f12c38af9057436c3882b5d2b5b86000272036207dbe39103bd927a173d54918dcd807a6292ddd722fb5359e0ccdbbf8b9a828570e517a115ff6e9ce0b5e6e88f05847a98a026224d8f027037ee7fdcb7424140f22e525a7598941271fa2a91328fa651b781a93f0b06c056d01efae7ab6b026882dc85cb86fbcd3c9f3ec4374937d96cbe61cb443e82aa681a25cf274a9dac3c9e8b6a1bc2ae61dcfa6f63ee3900026b384cdf9de188e8aeabcefc60b73662ef5205bd55ccc9b2b7f64d044cfc5d81e6e132889e251c30d1f7babea25014e5bb9d7420c18b7074607d1268d08dc68745ac74acea73ec1fa1737805ebf8f981f2f0bcc0f087110bbdaf387e2e0e50a14e0e696fc4f109fac12f6b32a2c5f065c769ef47ac1488c40e2abd4e21ce4dbb3bc460c004421037c3a6950cd5e1a1c802f8290d7cace2dc9806ec408cf27aff74ca4cfb0cf4ebc8906f18888e0f1e805f294f938ec12aacbbd9071add259431d2ea91563240287e20a4f5c22b247679958230c678be7d',
        userSalt: 'someSalt',
        algorithm: 'sha512',
        stretching: true,
        kuid,
        encryption: 'hmac'
      });
    },
    search: () => Promise.resolve({total: 1, hits: [{_id: 'foo2', kuid: 'someId'}]}),
    create: () => Promise.resolve({_id: 'foo', kuid: 'someId'}),
    update: () => Promise.resolve({_id: 'foo', kuid: 'someId'}),
    delete: () => Promise.resolve(true)
  };
};