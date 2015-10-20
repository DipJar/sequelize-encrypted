'use strict';

var crypto = require('crypto');
var _ = require('lodash');

exports.FIELD = 'ENCRYPTED_FIELD';
exports.VAULT = 'FIELD_VAULT';

var defaultVault = {
    algorithm: 'aes-256-cbc',
    ivLength: 16
};

function vault(DataTypes, config) {
    return {
        type: DataTypes.BLOB,
        field: config.field || config._vaultField,
        get: function() {
            var previous = this.getDataValue(config._vaultField);
            if (!previous) {
                return {};
            }

            previous = new Buffer(previous);

            var iv = previous.slice(0, config.ivLength);
            var content = previous.slice(config.ivLength, previous.length);
            var decipher = crypto.createDecipheriv(config.algorithm, config.key, iv);

            var json = decipher.update(content, undefined, 'utf8') + decipher.final('utf8');
            return JSON.parse(json);
        },
        set: function(value) {
            // if new data is set, we will use a new IV
            var newIv = crypto.randomBytes(config.ivLength);
            var cipher = crypto.createCipheriv(config.algorithm, config.key, newIv);

            cipher.end(JSON.stringify(value), 'utf-8');
            var encFinal = Buffer.concat([newIv, cipher.read()]);
            var previous = this.setDataValue(config._vaultField, encFinal);
        }
    };
};

exports.enVault = function(DataTypes, definition) {
    var vaultConfigs = {};
    function onlyVault() {
        var vaultCount = _.keys(vaultConfigs).length;
        if(vaultCount !== 1) {
            throw new Error('More than one vault in use. Must specify "vault" for all encrypted fields. ' + vaultCount + ' vaults.');
        }
        return _(vaultConfigs).values().last();
    }
    function normalizeIfMatching(thing, type) {
        if (thing === type) {
            return { type: type };
        } else if (_.get(thing, 'type') === type) {
            return thing;
        } else {
            return null;
        }
    }
    // two passes b/c we want to establish the vault first.
    return _.chain(definition).reduce(function(memo, v, k) {
        var match = normalizeIfMatching(v, exports.VAULT);
        if(match) {
            var vaultConfig = _.chain(defaultVault).clone().merge(match, { _vaultField: k }).value();
            // hex buffer for the key
            vaultConfig.key = new Buffer(vaultConfig.key, 'hex');
            vaultConfigs[k] = vaultConfig;
            memo[k]  = vault(DataTypes, vaultConfig);
        } else {
            memo[k] = v;
        }
        return memo;
    }, {}).reduce(function(memo, v, k) {
        var match = normalizeIfMatching(v, exports.FIELD);
        if (match) {
            var myVault = _.get(vaultConfigs, match.vault, onlyVault());
            memo[k] = {
                type: DataTypes.VIRTUAL,
                set: function(val) {
                    var encrypted = this[myVault._vaultField];
                    encrypted[k] = val;
                    this[myVault._vaultField] = encrypted;
                },
                get: function () {
                    var encrypted = this[myVault._vaultField];
                    return encrypted[k];
                }
            };
        } else {
            memo[k] = v;
        }
        return memo;
    }, {}).value();
};
