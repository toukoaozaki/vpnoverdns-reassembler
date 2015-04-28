#!/usr/bin/env python3
"""Run all tests.

Reference: http://stackoverflow.com/questions/1896918/running-unittest-with-typical-test-directory-structure
"""

import unittest

if __name__ == '__main__':
    # use the default shared TestLoader instance
    test_loader = unittest.defaultTestLoader
    # use the basic test runner that outputs to sys.stderr
    test_runner = unittest.TextTestRunner()
    # automatically discover all tests in the current dir of the form test*.py
    test_suite = test_loader.discover('.')
    # run the test suite
    test_runner.run(test_suite)
