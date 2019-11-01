# KeyChain for use with Web Cryptography API in Node.js

## Usage

Install the package

```bash
$ npm install https://github.com/anvilresearch/keychain.git
```

Load the module

```javascript
const KeyChain = require('keychain')
```

Create a new instance by passing a descriptive object to the `KeyChain` 
constructor. This object can have any naming or nesting scheme, as long as the last nested object contains parameters describing key generation. At a bare minimum, this must include an `alg` property with a JWA algorithm name as its value. Currently, `RS256`, `RS384`, and `RS512` are supported. 

```javascript
let keys = new KeyChain({
  a: { b: { alg: 'RS256' } },
  c: { d: { alg: 'RS256' } },
  e: { f: { alg: 'RS256', modulusLength: 2048 } // default is 4096
}) 
```

This initialized a KeyChain instance but didn't generate keys. To generate keys 
according to the object passed to the keychain, call `rotate()`. The `rotate()` 
method returns a promise for the keychain.

```javascript
keys.rotate()
```

Once keys have been generated, they can be accessed as CryptoKey or JWK objects, 
according to the object structure defined by the caller.

Access CryptoKey objects for Web Crypto API operations:

```javascript
keys.a.b.privateKey
keys.a.b.publicKey
```

Access JWK objects:

```javascript
keys.a.b.privateJwk
keys.a.b.publicJwk
```

Key rotation also generates a JWK Set in object and JSON form:

```javascript
keys.jwks     // JWK Set object
keys.jwkSet   // JWK Set JSON string
```

## Running tests

### Nodejs

```bash
$ npm test
```

## MIT License

[The MIT License](LICENSE.md)

Copyright (c) 2016 Anvil Research, Inc.
Copyright (c) 2017-2019 The Solid Project
