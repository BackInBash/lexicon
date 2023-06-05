"""Integration tests for STACKIT"""
from unittest import TestCase

from lexicon.tests.providers.integration_tests import IntegrationTestsV2


# Hook into testing framework by inheriting unittest.TestCase and reuse
# the tests which *each and every* implementation of the interface must
# pass, by inheritance from integration_tests.IntegrationTests
class STACKITProviderTests(TestCase, IntegrationTestsV2):
    """TestCase for STACKIT"""

    provider_name = "stackit"
    domain = "stackit-api-test.de"

    def _filter_headers(self):
        return ["Authorization"]
