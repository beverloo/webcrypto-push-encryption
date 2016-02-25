// Copyright 2016 Peter Beverloo. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

// Converts the |uint8Array| to an URL-safe base64 encoded string. When provided, |start| and |end|
// indicate the range within the |uint8Array| that should be converted.
function uint8ArrayToBase64Url(uint8Array, start, end) {
  start = start || 0;
  end = end || uint8Array.byteLength;

  const base64 = btoa(String.fromCharCode.apply(null, uint8Array.slice(start, end)));
  return base64.replace(/=/g, '')
               .replace(/\+/g, '-')
               .replace(/\//g, '_');
}

// Converts the URL-safe base64 encoded |base64UrlData| to an Uint8Array buffer.
function base64UrlToUint8Array(base64UrlData) {
  const padding = '='.repeat((4 - base64UrlData.length % 4) % 4);
  const base64 = (base64UrlData + padding).replace(/\-/g, '+')
                                          .replace(/_/g, '/');

  const rawData = atob(base64);
  const buffer = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i)
    buffer[i] = rawData.charCodeAt(i);

  return buffer;
}

module.exports = { uint8ArrayToBase64Url, base64UrlToUint8Array };
