import pytest

from friendly_captcha_client.client import FriendlyCaptchaClient

API_KEY = "test_api_key"
SITEKEY = "test_sitekey"


@pytest.fixture
def client():
    return FriendlyCaptchaClient(
        api_key=API_KEY,
        sitekey=SITEKEY,
        siteverify_endpoint="http://localhost",
        strict=False,
        verbose=True,
    )


@pytest.fixture
def strict_client():
    return FriendlyCaptchaClient(
        api_key=API_KEY,
        sitekey=SITEKEY,
        siteverify_endpoint="http://localhost",
        strict=True,
        verbose=True,
    )
