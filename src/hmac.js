// Copyright 2016 Peter Beverloo. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

// TODO: Document the HMAC class.
// TODO: Add input validation to the HMAC class.
class HMAC {
  constructor(ikm) {
    this.signPromise_ = crypto.subtle.importKey('raw', ikm, { name: 'HMAC', hash: 'SHA-256' },
                                                false /* extractable */, ['sign']);
  }

  sign(input) {
    return this.signPromise_.then(key => crypto.subtle.sign('HMAC', key, input));
  }
};

module.exports = HMAC;
