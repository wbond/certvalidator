# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

if sys.version_info < (3, 5):
    import imp
else:
    import importlib


def _import_from(mod, path, mod_dir=None):
    """
    Imports a module from a specific path

    :param mod:
        A unicode string of the module name

    :param path:
        A unicode string to the directory containing the module

    :param mod_dir:
        If the sub directory of "path" is different than the "mod" name,
        pass the sub directory as a unicode string

    :return:
        None if not loaded, otherwise the module
    """

    if mod in sys.modules:
        return sys.modules[mod]

    if mod_dir is None:
        mod_dir = mod

    if not os.path.exists(path):
        return None

    if not os.path.exists(os.path.join(path, mod_dir)):
        return None

    try:
        if sys.version_info < (3, 5):
            mod_info = imp.find_module(mod_dir, [path])
            return imp.load_module(mod, *mod_info)
        else:
            loader_details = (
                importlib.machinery.SourceFileLoader,
                importlib.machinery.SOURCE_SUFFIXES
            )
            finder = importlib.machinery.FileFinder(path, loader_details)
            spec = finder.find_spec(mod_dir)
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod] = module
            spec.loader.exec_module(module)
            return module
    except ImportError:
        return None


def make_suite():
    """
    Constructs a unittest.TestSuite() of all tests for the package. For use
    with setuptools.

    :return:
        A unittest.TestSuite() object
    """

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for test_class in test_classes():
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite


def test_classes():
    """
    Returns a list of unittest.TestCase classes for the package

    :return:
        A list of unittest.TestCase classes
    """

    # Make sure the module is loaded from this source folder
    tests_dir = os.path.dirname(os.path.abspath(__file__))

    _import_from(
        'certvalidator',
        os.path.join(tests_dir, '..')
    )

    from .test_certificate_validator import CertificateValidatorTests
    from .test_crl_client import CRLClientTests
    from .test_ocsp_client import OCSPClientTests
    from .test_registry import RegistryTests
    from .test_validate import ValidateTests

    return [
        CertificateValidatorTests,
        CRLClientTests,
        OCSPClientTests,
        RegistryTests,
        ValidateTests
    ]
