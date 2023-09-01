# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

from asn1crypto import pem, x509
from certvalidator import ocsp_client
from certvalidator.registry import CertificateRegistry
from certvalidator.context import ValidationContext
from certvalidator.validate import verify_ocsp_response

if sys.version_info < (3,):
    from urllib2 import HTTPError  # noqa
else:
    from urllib.error import HTTPError  # noqa

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPClientTests(unittest.TestCase):

    def test_fetch_ocsp(self):
        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            intermediate = x509.Certificate.load(cert_bytes)

        registry = CertificateRegistry()
        path = registry.build_paths(intermediate)[0]
        issuer = path.find_issuer(intermediate)

        try:
            ocsp_response = ocsp_client.fetch(intermediate, issuer)
        except (HTTPError) as e:
            # If we get a 500 error, retry to reduce test failures
            if e.code < 500 or e.code >= 600:
                raise
            ocsp_response = ocsp_client.fetch(intermediate, issuer)

        context = ValidationContext(ocsps=[ocsp_response])
        verify_ocsp_response(intermediate, path, context)
