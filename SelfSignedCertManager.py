from Crypto.PublicKey import RSA
from OpenSSL import crypto


class SelfSignedCertManager(object):

    def generate_self_signed_cert(self, cert_country, cert_state, cert_organization,
                                  cert_locality, cert_organizational_unit,
                                  cert_common_name, valid_days, serial_number):
        rsa_key = RSA.generate(2048)

        pk = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                    rsa_key.exportKey('PEM', pkcs=1))
        cert = crypto.X509()
        sub = cert.get_subject()
        sub.CN = cert_common_name
        sub.C = cert_country
        sub.ST = cert_state
        sub.L = cert_locality
        sub.O = cert_organization

        # optional
        if cert_organizational_unit:
            sub.OU = cert_organizational_unit

        cert.set_serial_number(serial_number)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(valid_days * 24 * 60 * 60)  # Valid for a year
        cert.set_issuer(sub)
        cert.set_pubkey(pk)
        cert.sign(pk, 'sha1')

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        private_key_pem = rsa_key.exportKey('PEM', pkcs=1)
        print('self signed printer certs generated.')

        return cert_pem, private_key_pem

    def generate_self_signed_root_cert(self, cert_country, cert_state, cert_organization,
                                       cert_locality, cert_organizational_unit,
                                       cert_common_name, valid_days, serial_number):
        rsa_key = RSA.generate(2048)

        pk = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                    rsa_key.exportKey('PEM', pkcs=1))
        cert = crypto.X509()
        sub = cert.get_subject()
        sub.CN = cert_common_name
        sub.C = cert_country
        sub.ST = cert_state
        sub.L = cert_locality
        sub.O = cert_organization

        # optional
        if cert_organizational_unit:
            sub.OU = cert_organizational_unit

        cert.set_serial_number(serial_number)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(valid_days * 24 * 60 * 60)  # Valid for a year
        cert.set_issuer(sub)
        cert.set_pubkey(pk)
        cert.sign(pk, 'sha1')

        root_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        root_private_key_pem = rsa_key.exportKey('PEM', pkcs=1)
        print('self signed printer root certs generated.')

        return root_cert_pem, root_private_key_pem

    def generate_root_ca_signed_cert(self, cert_country, cert_state, cert_organization,
                                     cert_locality, cert_organizational_unit,
                                     cert_common_name, valid_days, serial_number, root_cert_cn):
        rsa_key = RSA.generate(2048)

        pk = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                    rsa_key.exportKey('PEM', pkcs=1))
        cert = crypto.X509()
        sub = cert.get_subject()
        sub.CN = root_cert_cn
        sub.C = cert_country
        sub.ST = cert_state
        sub.L = cert_locality
        sub.O = cert_organization

        # optional
        if cert_organizational_unit:
            sub.OU = cert_organizational_unit

        cert.set_serial_number(serial_number)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(valid_days * 24 * 60 * 60)  # Valid for a year
        cert.set_issuer(sub)
        cert.set_pubkey(pk)
        cert.sign(pk, 'sha1')

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        private_key_pem = rsa_key.exportKey('PEM', pkcs=1)
        print('self signed printer certs generated.')

        return cert_pem, private_key_pem


if __name__ == "__main__":
    self_signed_cert_manager = SelfSignedCertManager()
    cert_pem, private_key_pem = self_signed_cert_manager.generate_root_ca_signed_cert(cert_country='IN',
                                                                                      cert_state='KA',
                                                                                      cert_organization='HP Inc',
                                                                                      cert_locality='Bangalore',
                                                                                      cert_organizational_unit='WPP',
                                                                                      cert_common_name='leaf.cert.test.hp.com',
                                                                                      valid_days=365,
                                                                                      serial_number=123456,
                                                                                      root_cert_cn='root.cert.test.hp.com')
    print(str(cert_pem))
    print(str(private_key_pem))
