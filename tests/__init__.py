# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

if sys.version_info < (3, 5):
    import imp
else:
    import importlib
    import importlib.abc
    import importlib.util


if sys.version_info >= (3, 5):
    class ModCryptoMetaFinder(importlib.abc.MetaPathFinder):
        def setup(self):
            self.modules = {}
            sys.meta_path.insert(0, self)

        def add_module(self, package_name, package_path):
            if package_name not in self.modules:
                self.modules[package_name] = package_path

        def find_spec(self, fullname, path, target=None):
            name_parts = fullname.split('.')
            if name_parts[0] not in self.modules:
                return None

            package = name_parts[0]
            package_path = self.modules[package]

            fullpath = os.path.join(package_path, *name_parts[1:])

            if os.path.isdir(fullpath):
                filename = os.path.join(fullpath, "__init__.py")
                submodule_locations = [fullpath]
            else:
                filename = fullpath + ".py"
                submodule_locations = None

            if not os.path.exists(filename):
                return None

            return importlib.util.spec_from_file_location(
                fullname,
                filename,
                loader=None,
                submodule_search_locations=submodule_locations
            )


    CUSTOM_FINDER = ModCryptoMetaFinder()
    CUSTOM_FINDER.setup()


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
        full_mod = mod
    else:
        full_mod = mod_dir.replace(os.sep, '.')

    if mod_dir is None:
        mod_dir = mod.replace('.', os.sep)

    if not os.path.exists(path):
        return None

    source_path = os.path.join(path, mod_dir, '__init__.py')
    if not os.path.exists(source_path):
        source_path = os.path.join(path, mod_dir + '.py')

    if not os.path.exists(source_path):
        return None

    if os.sep in mod_dir:
        append, mod_dir = mod_dir.rsplit(os.sep, 1)
        path = os.path.join(path, append)

    try:
        if sys.version_info < (3, 5):
            mod_info = imp.find_module(mod_dir, [path])
            return imp.load_module(mod, *mod_info)

        else:
            package = mod.split('.', 1)[0]
            package_dir = full_mod.split('.', 1)[0]
            package_path = os.path.join(path, package_dir)
            CUSTOM_FINDER.add_module(package, package_path)

            return importlib.import_module(mod)

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
