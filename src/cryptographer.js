// Copyright 2016 Peter Beverloo. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

const HKDF = require('./hkdf');
const KeyPair = require('./keypair');

// Utility function for UTF-8 encoding a string to an ArrayBuffer.
const utf8Encode = TextEncoder.prototype.encode.bind(new TextEncoder('utf-8'));

// Length, in bytes, of the salt that should be used for the message.
const SALT_BYTES = 16;

// Length, in bytes, of the prearranged authentication secret.
const AUTH_SECRET_BYTES = 16;

// Cryptographer that's able to encrypt and decrypt messages per the Web Push protocol's encryption.
// The cryptography is explained in ietf-webpush-encryption and ietf-httpbis-encryption-encoding:
//
// https://tools.ietf.org/html/draft-ietf-webpush-encryption
// https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding
//
// This implementation supports the drafts as of February 2016, requires an authentication secret
// to be used and allows for record padding between 0 and 65535 octets.
class WebPushCryptographer {
  // Constructs a new instance of the cryptographer. Both |senderKeys| and |receiverKeys| must be
  // instances of the KeyPair class, wherein the |senderKeys| must have a private key set. The
  // |authSecret| must be an ArrayBuffer containing 16 bytes containing the prearranged secret.
  constructor(senderKeys, receiverKeys, authSecret) {
    if (!(senderKeys instanceof KeyPair))
      throw new Error('The senderKeys must be an instance of the KeyPair class.');

    if (!senderKeys.privateKey)
      throw new Error('The senderKeys must have a private key set.');

    if (!(receiverKeys instanceof KeyPair))
      throw new Error('The receiverKeys must be an instance of the KeyPair class.');

    if (!(authSecret instanceof ArrayBuffer) && !(authSecret instanceof Uint8Array))
      throw new Error('The authSecret is expected to be an ArrayBuffer.');

    if (false && authSecret.byteLength != AUTH_SECRET_BYTES)
      throw new Error('The authSecret is expected to be ' + AUTH_SECRET_BYTES + ' bytes.');

    this.senderKeys_ = senderKeys;
    this.receiverKeys_ = receiverKeys;
    this.authSecret_ = new Uint8Array(authSecret);
  }

  // Gets the KeyPair instance representing the sender's key-pair.
  get senderKeys() { return this.senderKeys_; }

  // Gets the KeyPair instance representing the receiver's key-pair.
  get receiverKeys() { return this.receiverKeys_; }

  // Gets an Uint8Array containing the prearranged auth secret between the sender and receiver.
  get authSecret() { return this.authSecret_; }

  // Decrypts |ciphertext|, which must be an ArrayBuffer. The |salt| must be an ArrayBuffer
  // containing sixteen bytes of information. A promise will be returned that will be resolved with
  // the plaintext, as an ArrayBuffer, when the decryption operation has completed.
  decrypt(salt, ciphertext) {
    return this.deriveEncryptionKeys(salt).then(([contentEncryptionKey, nonce]) => {
      if (!(ciphertext instanceof ArrayBuffer))
        throw new Error('The ciphertext is expected to be an ArrayBuffer.');

      const algorithm = { name: 'AES-GCM', tagLength: 128, iv: nonce };

      return crypto.subtle.decrypt(algorithm, contentEncryptionKey, ciphertext);

    }).then(plaintext => {
      const plaintextBuffer = new Uint8Array(plaintext);
      if (plaintextBuffer.byteLength < 2)
        throw new Error('The plaintext is expected to contain at least the padding bytes.');

      const paddingLength = (plaintextBuffer[0] << 8) | plaintextBuffer[1];
      if (plaintextBuffer.byteLength < 2 + paddingLength)
        throw new Error('The plaintext does not contain enough data for the message\'s padding.');

      for (let i = 2; i < paddingLength + 2; ++i) {
        if (plaintextBuffer[i] != 0)
          throw new Error('The padding must only contain NULL-bytes.');
      }

      return plaintextBuffer.slice(2);
    });
  }

  // Encrypts |plaintext|, which must either be a string or an ArrayBuffer. The |salt| must be an
  // ArrayBuffer containing sixteen bytes of information. Optionally, up to 65535 bytes of padding
  // can be added by padding an |paddingBytes| argument. A promise will be returned that will be
  // resolved with an ArrayBuffer when the encryption operation has completed.
  encrypt(salt, plaintext, paddingBytes) {
    paddingBytes = paddingBytes || 0;

    return Promise.resolve().then(() => {
      if (!(plaintext instanceof ArrayBuffer))
        plaintext = utf8Encode(plaintext);

      if (paddingBytes < 0 || paddingBytes > 65535)
        throw new Error('The paddingBytes must be between 0 and 65535 (inclusive).');

      return this.deriveEncryptionKeys(salt);

    }).then(([contentEncryptionKey, nonce]) => {
      const record = new Uint8Array(2 + paddingBytes + plaintext.byteLength);
      record.set([ paddingBytes & 0xFF, paddingBytes >> 8 ]);
      record.fill(0, 2 /* sizeof(uint16_t) */, 2 + paddingBytes);
      record.set(new Uint8Array(plaintext), 2 + paddingBytes);

      const algorithm = { name: 'AES-GCM', tagLength: 128, iv: nonce };

      return crypto.subtle.encrypt(algorithm, contentEncryptionKey, record);
    });
  }

  // Derives the encryption keys to be used for this cryptographer. The returned promise will be
  // resolved with the {contentEncryptionKey, nonce, nonceInfo, cekInfo, IKM, PRK}. Note that only
  // the CEK and nonce will be used by this class, the rest is exposed for debugging purposes.
  deriveEncryptionKeys(salt) {
    return Promise.resolve().then(() => {
      if (!(salt instanceof ArrayBuffer) && !(salt instanceof Uint8Array))
        throw new Error('The salt is expected to be an ArrayBuffer.');

      if (salt.byteLength != SALT_BYTES)
        throw new Error('The salt is expected to be ' + SALT_BYTES + ' bytes.');

      salt = new Uint8Array(salt);

      return Promise.all([
        this.senderKeys_.deriveSharedSecret(this.receiverKeys_),

        this.senderKeys_.exportPublicKey(),
        this.receiverKeys_.exportPublicKey()
      ]);

    }).then(([ikm, senderPublic, receiverPublic]) => {
      // Info to use when extracting from the IKM and authentication secret HKDF.
      const authInfo = utf8Encode('Content-Encoding: auth\0');

      // Infos to use when extracting from the PRK and message salt HKDF.
      const contentEncryptionKeyInfo = this.deriveInfo('aesgcm', senderPublic, receiverPublic);
      const nonceInfo = this.deriveInfo('nonce', senderPublic, receiverPublic);

      // The first HKDF is fixed between the sender and receiver, whereas the second, per-message
      // HKDF incorporates the salt that is expected to be unique per message.
      const hkdf = new HKDF(ikm, this.authSecret_);
      return hkdf.extract(authInfo, 32).then(prk => {
        const messageHkdf = new HKDF(prk, salt);

        return Promise.all([
          messageHkdf.extract(contentEncryptionKeyInfo, 16).then(bits =>
              crypto.subtle.importKey(
                  'raw', bits, 'AES-GCM', true /* extractable */, ['decrypt', 'encrypt'])),
          messageHkdf.extract(nonceInfo, 12),
          contentEncryptionKeyInfo, nonceInfo, ikm, prk
        ]);
      });

    });
  }

  // Derives the info used for extracting the content encryption key and the nonce from the HKDF
  // created using the PRK and the message's salt. It combines a Content-Encoding header with a
  // given |contentEncoding| value with a |context| that contains the public keys of both the sender
  // and recipient. Both |senderPublic| and |receiverPublic| must be Uint8Arrays containing the
  // respective public keys in uncompressed EC form per SEC 2.3.3.
  //
  // context = label || 0x00 ||
  //           length(receiverPublic) || receiverPublic ||
  //           length(senderPublic) || senderPublic
  //
  // cek_info = "Content-Encoding: aesgcm" || 0x00 || context
  // nonce_info = "Content-Encoding: nonce" || 0x00 || context
  //
  // This method is synchronous, and will return an Uint8Array with the generated info buffer.
  deriveInfo(contentEncoding, senderPublic, receiverPublic) {
    const label = utf8Encode('P-256');  // always set to P-256

    let buffer = new Uint8Array(18 + contentEncoding.length + 1 + label.length + 1 + 2 * (2 + 65));
    let offset = 0;

    // Content-Encoding: |contentEncoding| || 0x00
    buffer.set(utf8Encode('Content-Encoding: '));
    buffer.set(utf8Encode(contentEncoding), 18);
    buffer.set([0x00], 18 + contentEncoding.length);

    offset += 18 + contentEncoding.length + 1;

    // label || 0x00
    buffer.set(label, offset);
    buffer.set([0x00], offset + label.length);

    offset += label.length + 1;

    // length(receiverPublic) || receiverPublic
    buffer.set([0x00, receiverPublic.byteLength], offset);
    buffer.set(receiverPublic, offset + 2);

    offset += 2 + receiverPublic.byteLength;

    // length(senderPublic) || senderPublic
    buffer.set([0x00, senderPublic.byteLength], offset);
    buffer.set(senderPublic, offset + 2);

    return buffer;
  }
};

module.exports = WebPushCryptographer;
