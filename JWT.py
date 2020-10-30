import datetime
import time
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jwcrypto import jwe
from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto.common import base64url_encode
from jwcrypto.common import json_encode


class JwePostcard:

    def generate_header_data(self, kid, jti):
        jti = str(uuid.uuid4())
        current_time = int(round(time.time() * 1000))
        return json_encode({"alg": "dir",
                            "enc": "A128GCM",
                            "cty": "application/json",
                            "zip": "DEF",
                            "kid": kid,
                            "jti": jti,
                            "iat": current_time})

    def jwe_encrypt(self, payload, header, key):
        jwetoken = jwe.JWE(payload.encode('utf-8'), header)
        params = dict()
        params['kty'] = 'oct'
        params['k'] = base64url_encode(key)
        jwetoken.add_recipient(jwk.JWK(**params))
        print("JWE encryption successful")
        return jwetoken.serialize(compact=True)

    def jwe_decrypt(self, jwe_payload, key):
        jwetoken = jwe.JWE()
        jwetoken.deserialize(raw_jwe=jwe_payload)
        params = dict()
        params['kty'] = 'oct'
        params['k'] = base64url_encode(key)
        print("JWE decryption successful.")
        jwetoken.decrypt(jwk.JWK(**params))
        return jwetoken.payload


class JwsPostcard(object):

    def sign(self, payload, private_key_pem_data, header_json_data):
        jwstoken = jws.JWS(payload.encode('utf-8'))
        rsa_private_key = jwk.JWK.from_pem(private_key_pem_data)
        jwstoken.add_signature(key=rsa_private_key, protected=header_json_data)
        sign = jwstoken.serialize(compact=True)
        print("JWS signing successful. serialized data: {}")
        return sign

    def generate_header_data(self, cert_pem_data):
        cert = x509.load_pem_x509_certificate(cert_pem_data, backend=default_backend())
        de_serialized_cert_pem = cert_pem_data.decode('utf-8')[27:-25]
        base64_url_cert_fingerprint = base64url_encode(cert.fingerprint(hashes.SHA256()))
        return {"alg": "PS256", "x5c": [cert_pem_data.decode('utf-8')],
                "cty": "vnd.hp.cdm.service.postcard.version.2.resource.keyExchange+json",
                "x5t#S256": base64_url_cert_fingerprint}

    def verify(self, jws_payload, public_key_pem_data):
        jwstoken = jws.JWS()
        jwstoken.deserialize(raw_jws=jws_payload)
        jwk_token = jwk.JWK()
        jwk_token.import_from_pem(public_key_pem_data)
        jwstoken.verify(jwk_token)
        payload = jwstoken.payload
        print(payload)
        return payload

class RsaUtil(object):

    def generate_rsa_keypair(self):
        # Generate our key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, backend=default_backend(),
        )
        return key

    def get_public_key_pem(self, key):
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem

    def get_private_key_pem(self, key):
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_pem

    def sign_with_self_signed_cert(self, key):
        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"KA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"test.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(key, hashes.SHA256(), backend=default_backend())
        return cert


if __name__ == "__main__":
    rsa_utility = RsaUtil()
    key = rsa_utility.generate_rsa_keypair();
    cert = rsa_utility.sign_with_self_signed_cert(key)
    public_pem = rsa_utility.get_public_key_pem(key)
    private_pem = rsa_utility.get_private_key_pem(key)

    crypto = JwsPostcard()
    payload = "My Integrity protected message"

    jws_header_json = crypto.generate_header_data(cert.public_bytes(serialization.Encoding.PEM))
    print(jws_header_json)

    sign = crypto.sign(payload, private_pem, jws_header_json)
    signature_verified_payload = crypto.verify(jws_payload=sign, public_key_pem_data= public_pem)
    print(signature_verified_payload)
