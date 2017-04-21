# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

from asn1crypto import pem, x509
from asn1crypto.util import timezone
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CertificateValidatorTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def _load_trust_roots(self, path):
            rootCertificates = []
            certificates = os.listdir(path)
            certificate_files = [cert for cert in certificates if '.crt' in cert]
            for certificate_file_name in certificate_files:
                rootCertificates.append(self._load_cert_object('root_certs', certificate_file_name))
            return rootCertificates

    def test_basic_certificate_validator_tls(self):
        cert = self._load_cert_object('codex.crt')
        other_certs = [self._load_cert_object('GeoTrust_EV_SSL_CA_-_G4.crt')]

        moment = datetime(2015, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        path = validator.validate_tls('codexns.io')
        self.assertEqual(3, len(path))

    def test_basic_certificate_validator_tls_expired(self):
        cert = self._load_cert_object('codex.crt')
        other_certs = [self._load_cert_object('GeoTrust_EV_SSL_CA_-_G4.crt')]

        validator = CertificateValidator(cert, other_certs)

        with self.assertRaisesRegexp(PathValidationError, 'expired'):
            validator.validate_tls('codexns.io')

    def test_basic_certificate_validator_tls_invalid_hostname(self):
        cert = self._load_cert_object('codex.crt')
        other_certs = [self._load_cert_object('GeoTrust_EV_SSL_CA_-_G4.crt')]

        moment = datetime(2015, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegexp(PathValidationError, 'not valid'):
            validator.validate_tls('google.com')

    def test_basic_certificate_validator_tls_invalid_key_usage(self):
        cert = self._load_cert_object('codex.crt')
        other_certs = [self._load_cert_object('GeoTrust_EV_SSL_CA_-_G4.crt')]

        moment = datetime(2015, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(moment=moment)
        validator = CertificateValidator(cert, other_certs, context)

        with self.assertRaisesRegexp(PathValidationError, 'for the purpose'):
            validator.validate_usage(set(['crl_sign']))

    def test_basic_certificate_validator_tls_whitelist(self):
        cert = self._load_cert_object('codex.crt')
        other_certs = [self._load_cert_object('GeoTrust_EV_SSL_CA_-_G4.crt')]

        context = ValidationContext(whitelisted_certs=[cert.sha1_fingerprint])
        validator = CertificateValidator(cert, other_certs, context)

        # If whitelist does not work, this will raise exception for expiration
        validator.validate_tls('codexns.io')

        # If whitelist does not work, this will raise exception for hostname
        validator.validate_tls('google.com')

        # If whitelist does not work, this will raise exception for key usage
        validator.validate_usage(set(['crl_sign']))

    def test_crl_without_update_field(self):
        cert = self._load_cert_object('microsoft_armored.crt')
        root_certificates = self._load_trust_roots(os.path.join(fixtures_dir, 'root_certs'))
        moment = datetime(2009, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        context = ValidationContext(trust_roots=root_certificates, moment=moment,
                                    allow_fetching=True)
        validator = CertificateValidator(cert, validation_context=context)
        validator.validate_usage(set(['digital_signature']), set(['code_signing']), False)

    def test_crl_without_update_field_hard_fail(self):
        cert = self._load_cert_object('microsoft_armored.crt')
        root_certificates = self._load_trust_roots(os.path.join(fixtures_dir, 'root_certs'))
        moment = datetime(2009, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        context = ValidationContext(trust_roots=root_certificates, moment=moment,
                                    allow_fetching=True, revocation_mode='hard-fail')
        validator = CertificateValidator(cert, validation_context=context)
        with self.assertRaisesRegexp(PathValidationError, 'nextUpdate field is expected to be present in CRL'):
            validator.validate_usage(set(['digital_signature']), set(['code_signing']), False)