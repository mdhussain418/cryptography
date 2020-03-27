from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

message = 'rsassa_pkcs_1.py'

### reading pem file from location
key = RSA.importKey(open('/tmp/private_key.pem').read())

### generating private key from modulus and exponent
## converting hex string to int
# public_exponent = long('10001', 16)
# public_modulus = int('83A73A4FBF789...', 16)
# private_exponent = long('83A73A4FBF789EA7E', 16)
# key = construct((public_modulus, public_exponent, private_exponent))

h = SHA256.new(message)
print(h.hexdigest())

signature = PKCS1_PSS.new(key, saltLen=16).sign(h)
base64_signature = base64.b64encode(signature)
print(base64_signature)
