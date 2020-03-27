from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

message = 'rsassa_pkcs_1.py'

### reading pem file from location
key = RSA.importKey(open('remote_attest_simulator_privatekey.pem').read())

### generating private key from modulus and exponent
## converting hex string to int
exponent = long('10001', 16)
modulus = int('83A73A4FBF789...', 16)

key = construct((modulus, exponent))

h = SHA256.new(message)
print(h.hexdigest())

signature = PKCS1_PSS.new(key, saltLen=16).sign(h)
base64EncodedSignature = base64.b64encode(signature)
print(base64EncodedSignature)
