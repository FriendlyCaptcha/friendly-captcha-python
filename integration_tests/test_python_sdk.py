import requests
import pytest

from friendly_captcha_client.client import FriendlyCaptchaClient

MOCK_SERVER_URL = "http://localhost:1090"
API_ENDPOINT = "/api/v2/captcha/siteverify"
TEST_ENDPOINT = "/api/v1/tests"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Frc-Sdk": "friendly-captcha-python-sdk@99.99.99",
}


def fetch_test_cases_from_server(endpoint: str):
    """Fetch test cases from the mock server."""
    response = requests.get(endpoint)

    if response.status_code != 200:
        raise Exception(
            f"Failed to fetch test cases. Server responded with: {response.status_code}: {response.text}"
        )

    return response.json()


def is_mock_server_running(url):
    """Check if the mock server is running."""
    try:
        response = requests.get(url, timeout=0.5)
        return response.status_code == 200
    except requests.ConnectionError:
        return False


@pytest.mark.skipif(
    not is_mock_server_running(MOCK_SERVER_URL + TEST_ENDPOINT),
    reason="Mock server is not running, skipping integration test.",
)
def test_python_sdk():
    test_data = fetch_test_cases_from_server(MOCK_SERVER_URL + TEST_ENDPOINT)

    for test in test_data["tests"]:
        frc_client = FriendlyCaptchaClient(
            api_key="FRC_APIKEY",
            sitekey="FRC_SITEKEY",
            siteverify_endpoint=f"{MOCK_SERVER_URL}{API_ENDPOINT}",
            strict=bool(test["strict"]),
        )

        response = frc_client.verify_captcha_response(
            captcha_response=test["response"],
            timeout=10,
        )
        assert (
            response.should_accept == test["expectation"]["should_accept"]
        ), f"Test {test['name']} failed [should accept]!"
        assert (
            response.was_able_to_verify == test["expectation"]["was_able_to_verify"]
        ), f"Test {test['name']} failed [was able to verify]!"
        assert (
            response.is_client_error == test["expectation"]["is_client_error"]
        ), f"Test {test['name']} failed [is client error]!"
        print(f"Tests {test['name']} passed!")

    print("All tests passed!")
