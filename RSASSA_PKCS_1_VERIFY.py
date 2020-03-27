from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
import base64
from Crypto.PublicKey.RSA import construct
import binascii

### generating public key from exponent and modulus
e = long('10001', 16)
n = int('83A73A4FBF....', 16)
key = construct((n, e))

### generating public key from pem file
# key = RSA.importKey(open('/tmp/public_key.pem').read())

message = 'rsassa_pkcs_1.py'
h = SHA256.new(message)
print(h.hexdigest())

signature = base64.decodestring('base64 encoded value of signature..')
result = PKCS1_PSS.new(key, saltLen=16).verify(h, signature)
print(result)
