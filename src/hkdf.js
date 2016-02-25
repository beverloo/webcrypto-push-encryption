// Copyright 2016 Peter Beverloo. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

const HMAC = require('./hmac');

// TODO: Document the HKDF class.
// TODO: Add input validation to the HKDF class.
class HKDF {
  constructor(ikm, salt) {
    const hmac = new HMAC(salt);

    this.extractPromise_ = hmac.sign(ikm).then(prk => new HMAC(prk));
  }

  extract(rawInfo, byteLength) {
    let info = new Uint8Array(rawInfo.byteLength + 1);
    info.set(rawInfo);
    info.set([1], rawInfo.length);

    return this.extractPromise_.then(prkHmac => prkHmac.sign(info))
                               .then(hash => hash.slice(0, byteLength));
  }
};

module.exports = HKDF;
