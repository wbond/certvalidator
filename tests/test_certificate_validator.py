# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from oscrypto import asymmetric
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathBuildingError, PathValidationError

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CertificateValidatorTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def _load_smime_cert(self, filename):
        return self._load_cert_object('rfc9216', filename)

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def test_basic_certificate_validator_tls(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        path = validator.validate_tls('www.mozilla.org')

        expected_names = [
            "Common Name: DigiCert Global Root CA, Organizational Unit: www.digicert.com, "
            "Organization: DigiCert Inc, Country: US",
            "Common Name: DigiCert SHA2 Secure Server CA, Organization: DigiCert Inc, Country: US",
            "Common Name: www.mozilla.org, Organizational Unit: WebOps, Organization: Mozilla Corporation, "
            "Locality: Mountain View, State/Province: California, Country: US",
        ]
        expected_hashes = [
            b'\x80Q\x06\x012\xad\x9a\xc2}Q\x87\xa0\xe8\x87\xfb\x01b\x01U\xee',
            b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
            b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81'
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    def test_basic_certificate_validator_tls_expired(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'expired'):
            validator.validate_tls('www.mozilla.org')

    def test_basic_certificate_validator_tls_invalid_hostname(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'not valid'):
            validator.validate_tls('google.com')

    def test_basic_certificate_validator_tls_invalid_key_usage(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegex(PathValidationError, 'for the purpose'):
            validator.validate_usage(set(['crl_sign']))

    def test_basic_certificate_validator_tls_whitelist(self):
        cert = self._load_cert_object('mozilla.org.crt')
        other_certs = [self._load_cert_object('digicert-sha2-secure-server-ca.crt')]

        moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(
            whitelisted_certs=[cert.sha1_fingerprint],
            moment=moment
        )
        validator = CertificateValidator(cert, other_certs, context)

        # If whitelist does not work, this will raise exception for expiration
        validator.validate_tls('www.mozilla.org')

        # If whitelist does not work, this will raise exception for hostname
        validator.validate_tls('google.com')

        # If whitelist does not work, this will raise exception for key usage
        validator.validate_usage(set(['crl_sign']))

    def test_basic_certificate_validator_rsa_smime_sig(self):
        cert = self._load_smime_cert('alice@smime.example.sig.pem')
        root_certs = [self._load_smime_cert('Sample_LAMPS_RSA_Certification_Authority.selfsigned.pem')]

        moment = datetime(2022, 4, 21, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(trust_roots=root_certs, moment=moment)
        validator = CertificateValidator(cert, validation_context=context)

        path = validator.validate_usage(
            set(['digital_signature']),
            set(['email_protection'])
        )

        expected_names = [
            "Common Name: Sample LAMPS RSA Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Alice Lovelace, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
        ]
        expected_hashes = [
            b'HkZ\x81\tDM\xbb\r\x8c\x89\x7f\x08\xaa\xa5\xf2\xfb+\xc0\xb1',
            b'*\x86\x97\xa3\x9a^}8\xf6\n\x96\x10\xb7M\xfb}m%,&',
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    @unittest.skipIf(not hasattr(asymmetric, "eddsa_verify"),
                     "EdDSA not supported in this oscrypto version")
    def test_basic_certificate_validator_eddsa_smime_sig(self):
        cert = self._load_smime_cert('carlos@smime.example.sig.pem')
        root_certs = [self._load_smime_cert('Sample_LAMPS_Ed25519_Certification_Authority.selfsigned.pem')]

        moment = datetime(2022, 4, 21, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(trust_roots=root_certs, moment=moment)
        validator = CertificateValidator(cert, validation_context=context)

        path = validator.validate_usage(
            set(['digital_signature', 'non_repudiation']),
            set(['email_protection'])
        )

        expected_names = [
            "Common Name: Sample LAMPS Ed25519 Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Carlos Turing, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
        ]
        expected_hashes = [
            b'\x05,gW\xc7\xfd\\g\xb0$$\x7f\xd84-FJ\x94$.',
            b'h\t\xcd\x86\xc8|P\xa0\x187vYSL^\xb1\x9f\xfe\xc9\x1d',
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    @unittest.skipIf(not hasattr(asymmetric, "eddsa_verify"),
                     "EdDSA not supported in this oscrypto version")
    def test_basic_certificate_validator_eddsa_smime_enc(self):
        cert = self._load_smime_cert('carlos@smime.example.enc.pem')
        root_certs = [self._load_smime_cert('Sample_LAMPS_Ed25519_Certification_Authority.selfsigned.pem')]

        moment = datetime(2022, 4, 21, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(trust_roots=root_certs, moment=moment)
        validator = CertificateValidator(cert, validation_context=context)

        path = validator.validate_usage(
            set(['key_agreement']),
            set(['email_protection'])
        )

        expected_names = [
            "Common Name: Sample LAMPS Ed25519 Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Carlos Turing, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
        ]
        expected_hashes = [
            b'\x05,gW\xc7\xfd\\g\xb0$$\x7f\xd84-FJ\x94$.',
            b'h\t\xcd\x86\xc8|P\xa0\x187vYSL^\xb1\x9f\xfe\xc9\x1d',
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    @unittest.skipIf(not hasattr(asymmetric, "eddsa_verify"),
                     "EdDSA not supported in this oscrypto version")
    def test_cross_rsa_certificate_validator_eddsa_smime_sig(self):
        cert = self._load_smime_cert('dana@smime.example.sig.pem')
        root_certs = [self._load_smime_cert('Sample_LAMPS_Ed25519_Certification_Authority.crosssigned.pem')]
        cross_certs = [self._load_smime_cert('Sample_LAMPS_RSA_Certification_Authority.selfsigned.pem')]

        moment = datetime(2022, 4, 21, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(trust_roots=cross_certs, moment=moment)
        validator = CertificateValidator(cert, root_certs, validation_context=context)

        path = validator.validate_usage(
            set(['digital_signature', 'non_repudiation']),
            set(['email_protection'])
        )

        expected_names = [
            "Common Name: Sample LAMPS RSA Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Sample LAMPS Ed25519 Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Dana Hopper, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
        ]
        expected_hashes = [
            b'HkZ\x81\tDM\xbb\r\x8c\x89\x7f\x08\xaa\xa5\xf2\xfb+\xc0\xb1',
            b'\x05,gW\xc7\xfd\\g\xb0$$\x7f\xd84-FJ\x94$.',
            b'\tPP\xe6\xee\x8d\x82\xe7R\x920N\x1a\x96!\t\x95\x1d\x11\x8e',
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    @unittest.skipIf(not hasattr(asymmetric, "eddsa_verify"),
                     "EdDSA not supported in this oscrypto version")
    def test_cross_eddsa_certificate_validator_rsa_smime_sig(self):
        cert = self._load_smime_cert('bob@smime.example.sig.pem')
        root_certs = [self._load_smime_cert('Sample_LAMPS_RSA_Certification_Authority.crosssigned.pem')]
        cross_certs = [self._load_smime_cert('Sample_LAMPS_Ed25519_Certification_Authority.selfsigned.pem')]

        moment = datetime(2022, 4, 21, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(trust_roots=cross_certs, moment=moment)
        validator = CertificateValidator(cert, root_certs, validation_context=context)

        path = validator.validate_usage(
            set(['digital_signature', 'non_repudiation']),
            set(['email_protection'])
        )

        expected_names = [
            "Common Name: Sample LAMPS Ed25519 Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Sample LAMPS RSA Certification Authority, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
            "Common Name: Bob Babbage, "
            "Organizational Unit: LAMPS WG, Organization: IETF",
        ]
        expected_hashes = [
            b'\x05,gW\xc7\xfd\\g\xb0$$\x7f\xd84-FJ\x94$.',
            b'HkZ\x81\tDM\xbb\r\x8c\x89\x7f\x08\xaa\xa5\xf2\xfb+\xc0\xb1',
            b"\xe7\x189h\xd9+_F\xce\x0b\xc8\xfb\xdc'\xd1\xf6\xfe]\xb1\xcd",
        ]

        names = [item.subject.human_friendly for item in path]
        hashes = [item.subject.sha1 for item in path]

        if len(path) == 2 and hashes == expected_hashes[1:]:
            self.assertEqual(expected_names[1:], names)
            self.assertEqual(expected_hashes[1:], hashes)
        else:
            self.assertEqual(expected_names, names)
            self.assertEqual(expected_hashes, hashes)

    @unittest.skipIf(not hasattr(asymmetric, "eddsa_verify"),
                     "EdDSA not supported in this oscrypto version")
    def test_non_cross_rsa_eddsa_smime(self):
        cert = self._load_smime_cert('bob@smime.example.sig.pem')
        root_certs = [self._load_smime_cert('Sample_LAMPS_Ed25519_Certification_Authority.crosssigned.pem')]

        moment = datetime(2022, 4, 21, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(trust_roots=root_certs, moment=moment)
        validator = CertificateValidator(cert, validation_context=context)

        with self.assertRaisesRegex(PathBuildingError, "no issuer matching \"Common Name: Sample LAMPS RSA"):
            validator.validate_usage(
                set(['digital_signature', 'non_repudiation']),
                set(['email_protection'])
            )
