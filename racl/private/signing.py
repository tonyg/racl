# Uses PyNaCl to produce test data that can be checked against other
# implementations that merge nacl-20110221 with SUPERCOP's Ed25519
# signature scheme.

import nacl.signing
import nacl.hash

k = nacl.signing.SigningKey(nacl.hash.sha512('This is my passphrase').decode('hex')[:32])
print k._seed.encode('hex')
print k._signing_key.encode('hex')
