const { KafkaEncryption } = require('confluent-encryption-azure');
const { Buffer } = require('buffer');
const { NestedPropertyAccessor } = C.expr;
const cLogger = C.util.getLogger('func:confluentDecryptor');

exports.name = 'Confluent Decrypt';
exports.version = '1.0';
exports.group = 'Custom Functions';
exports.disabled = 0;

let conf = {};
let srcEncryptedKey;
let srcEncryptedValue;
let dstDecryptedKey;
let dstDecryptedValue;
let keyDecrypter;
let valueDecrypter;
let encryptConfig;
let azureKeyName;
let azureVaultName;

exports.init = async (opt) => {

  cLogger.info("Initializing confluentDecryptor...");
  conf = (opt || {}).conf || {};
  srcEncryptedKey = new NestedPropertyAccessor((conf.srcEncryptedKey || '').trim());
  srcEncryptedValue = new NestedPropertyAccessor((conf.srcEncryptedValue || '').trim());
  azureKeyName = (conf.azureKeyName || '').trim();
  azureVaultName = (conf.azureVaultName || '').trim();

  dstDecryptedKey = (conf.dstDecryptedKey || '').trim();
  dstDecryptedValue = (conf.dstDecryptedValue || '').trim();

  if (dstDecryptedKey) {
    dstDecryptedKey = new NestedPropertyAccessor(dstDecryptedKey);
  }

  if (dstDecryptedValue) {
    dstDecryptedValue = new NestedPropertyAccessor(dstDecryptedValue);
  }

  encryptConfig = {
    'providers.chain': 'cached > generator > azure',
    'cached.provider.type': 'cached',
    'generator.provider.type': 'generator',
    'generator.symetric.key.size': '256',
    'azure.provider.type': 'azure',
    'value.deserializer.encryption.key': azureKeyName,
    'key.deserializer.encryption.key': azureKeyName,
    //'value.deserializer.wrapping.key': azureKeyName,         // Couldn't get anything with this value to work
    // 'key.deserializer.wrapping.key': azureKeyName,           // Couldn't get anything with this value to work
    // 'key.deserializer.key.properties': 'iv=1234567891234567',// Couldn't get anything with this value to work
    // 'value.serializer.key.properties': 'iv=1234567891234567',// Couldn't get anything with this value to work
    'azure.provider.vault.name': azureVaultName
  }

  try {
    keyDecrypter = new KafkaEncryption({ config: encryptConfig, isKey: true });
    valueDecrypter = new KafkaEncryption({ config: encryptConfig, isKey: false });
  } catch (e) {
    cLogger.warn("Could not instantiate KafkaEncryption: " + e)
  }
};

// The Encrypted Data has to be a Uint8Array, so this attempts to convert the fields to the appropriate type.
function convertData(value) {
  const results = new Uint8Array(value.length);
  try {
    for (let i = 0; i < value.length; i++) {
      results[i] = value.charCodeAt(i);
    }
    return results;
  } catch (error) {
    // Log if there was an error when attempting to convert.
    cLogger.error(`There was an error when attempting to convert the field to a Uint8Array: ` + error);
  }
}

exports.process = async (event) => {
  let resultsValue;
  let resultsKey;
  try {
    const encryptedKey = convertData(srcEncryptedKey.get(event));
    const decryptedKey = await keyDecrypter.decrypt(Buffer.from(encryptedKey));
    resultsKey = Buffer.from(decryptedKey).toString();
  } catch (error) {
    cLogger.error('There was an error that occurred when attempting to decrypt the key: ' + error)
  }

  try {
    const encryptedValue = convertData(srcEncryptedValue.get(event));
    const decryptedValue = await valueDecrypter.decrypt(Buffer.from(encryptedValue));
    resultsValue = Buffer.from(decryptedValue).toString();
  } catch (error) {
    cLogger.error('There was an error that occurred when attempting to decrypt the value: ' + error)
  }

  dstDecryptedKey.set(event, resultsKey.toString());
  dstDecryptedValue.set(event, resultsValue.toString());
  return event;
}
