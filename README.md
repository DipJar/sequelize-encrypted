# sequelize-encrypted

Encrypted fields for Sequelize ORM

```js
var Sequelize = require('sequelize')
var enc = require('sequelize-encrypted');

var User = sequelize.define('user', enc.enVault({
    name: Sequelize.STRING,
    vault: {
       type: enc.VAULT,
       // secret key should be 32 bytes hex encoded (64 characters)
       key: process.env.SECRET_KEY,
       // field: 'legacy_blob_field_name',
       // algorithm: 'aes-256-cbc,
       // ivLength: 16
    },
    // encrypted virtual fields
    private_1: enc.FIELD,
    private_2: {
       type: enc.FIELD
    }
}));

var user = User.build();
user.private_1 = 'test';
```

## How it works

The `withVault` adds a sequelize BLOB field to the model configured with getters/setters for decrypting and encrypting data. Encrypted JSON encodes the value you set and then encrypts this value before storing in the database.

Additionally, is a `FIELD` type that is replaced with a sequelize VIRTUAL field that provides access to specific fields in the encrypted vault. It is recommended that these are used to get/set values versus using the encrypted field directly.

## Generating a key

By default, AES-SHA256-CBC is used to encrypt data. You should generate a random key that is 32 bytes.

```
openssl rand -hex 32
```

Do not save this key with the source code, ideally you should use an environment variable or other configuration injection to provide the key during app startup.

## Tips

You might find it useful to override the default `toJSON` implementation for your model to omit the encrypted field or other sensitive fields.

## License

MIT
