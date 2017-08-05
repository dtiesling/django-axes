from django.test import TestCase, override_settings

from axes.utils import get_ip
from axes.conf import settings


@override_settings(AXES_BEHIND_REVERSE_PROXY=True)
class AccessAttemptTest(TestCase):
    def test_failure_limit_once(self):
        print(settings.AXES_BEHIND_REVERSE_PROXY)
        # get_ip({})
