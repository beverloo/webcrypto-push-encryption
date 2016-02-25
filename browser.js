// Copyright 2016 Peter Beverloo. All rights reserved.
// Use of this source code is governed by the MIT license, a copy of which can
// be found in the LICENSE file.

// Exposes the KeyPair and WebPushCryptographer functions on the global scope.
global.KeyPair = require('./src/keypair');
global.WebPushCryptographer = require('./src/cryptographer');
