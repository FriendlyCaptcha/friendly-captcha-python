import json
from operator import contains
import pytest
import requests

from friendly_captcha_client.client import (
    FriendlyCaptchaClient,
    RiskIntelligenceRetrieveResult,
)
from friendly_captcha_client.schemas import (
    FriendlyCaptchaResponse,
    RiskIntelligenceRetrieveResponse,
)

MOCK_SERVER_URL = "http://localhost:1090"

CAPTCHA_SITEVERIFY_TESTS_ENDPOINT = "/api/v1/captcha/siteverifyTests"
RISK_INTELLIGENCE_RETRIEVE_TESTS_ENDPOINT = "/api/v1/riskIntelligence/retrieveTests"


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
    not is_mock_server_running(MOCK_SERVER_URL + CAPTCHA_SITEVERIFY_TESTS_ENDPOINT),
    reason="Mock server is not running, skipping integration test.",
)
def test_python_sdk_captcha_siteverify():
    test_data = fetch_test_cases_from_server(
        MOCK_SERVER_URL + CAPTCHA_SITEVERIFY_TESTS_ENDPOINT
    )

    for test in test_data["tests"]:
        frc_client = FriendlyCaptchaClient(
            api_key="FRC_APIKEY",
            sitekey="FRC_SITEKEY",
            api_endpoint=MOCK_SERVER_URL,
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

        # When verification succeeded, compare data to expected siteverify response
        if response.data is not None:
            raw = test.get("siteverify_response")
            if raw is not None:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict) and data.get("success"):
                    expected_response = FriendlyCaptchaResponse.model_validate(data)
                    exp = expected_response.data
                    res = response.data
                    assert exp is not None, "Expected response data is missing"

                    assert (
                        exp.event_id == res.event_id
                    ), f"Test {test['name']}: Event ID does not match expected value"
                    assert (
                        exp.challenge == res.challenge
                    ), f"Test {test['name']}: Challenge data does not match expected value"
                    assert (
                        exp.risk_intelligence == res.risk_intelligence
                    ), f"Test {test['name']}: Risk Intelligence data does not match expected value"

                    if exp.risk_intelligence is not None:
                        assert contains(
                            json.dumps(res.risk_intelligence_raw), "header_user_agent"
                        ), f"Test {test['name']}: Risk Intelligence raw data does not contain 'header_user_agent'"

                    # Check specific fields
                    if (
                        exp.risk_intelligence is not None
                        and res.risk_intelligence is not None
                    ):
                        assert (
                            exp.risk_intelligence.client.header_user_agent
                            == res.risk_intelligence.client.header_user_agent
                        ), f"Test {test['name']}: header_user_agent does not match"
                        exp_browser = exp.risk_intelligence.client.browser
                        res_browser = res.risk_intelligence.client.browser
                        if exp_browser is not None and res_browser is not None:
                            assert (
                                exp_browser.id == res_browser.id
                            ), f"Test {test['name']}: client.browser.id does not match"

        print(f"Tests {test['name']} passed!")

    print("All tests passed!")


@pytest.mark.skipif(
    not is_mock_server_running(
        MOCK_SERVER_URL + RISK_INTELLIGENCE_RETRIEVE_TESTS_ENDPOINT
    ),
    reason="Mock server is not running, skipping integration test.",
)
def test_python_sdk_risk_intelligence_retrieve():
    test_data = fetch_test_cases_from_server(
        MOCK_SERVER_URL + RISK_INTELLIGENCE_RETRIEVE_TESTS_ENDPOINT
    )

    for test in test_data["tests"]:
        frc_client = FriendlyCaptchaClient(
            api_key="FRC_APIKEY",
            sitekey="FRC_SITEKEY",
            api_endpoint=MOCK_SERVER_URL,
            strict=False,
        )

        response: RiskIntelligenceRetrieveResult = (
            frc_client.retrieve_risk_intelligence(
                token=test["token"],
                timeout=10,
            )
        )

        assert (
            response.was_able_to_retrieve == test["expectation"]["was_able_to_retrieve"]
        ), f"Test {test['name']} failed [was able to retrieve]!"
        assert (
            response.is_client_error == test["expectation"]["is_client_error"]
        ), f"Test {test['name']} failed [is client error]!"
        assert (
            response.is_valid == test["expectation"]["is_valid"]
        ), f"Test {test['name']} failed [is valid token]!"
        if response.data is not None:
            raw = test.get("retrieve_response")
            if raw is not None:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict) and data.get("success"):
                    expected_response = RiskIntelligenceRetrieveResponse.model_validate(
                        data
                    )
                    exp = expected_response.data
                    res = response.data
                    assert exp is not None, "Expected retrieve data is missing"

                    assert (
                        exp.event_id == res.event_id
                    ), f"Test {test['name']}: Event ID does not match expected value"
                    assert (
                        exp.token == res.token
                    ), f"Test {test['name']}: Retrieve token does not match expected value"
                    assert (
                        exp.risk_intelligence == res.risk_intelligence
                    ), f"Test {test['name']}: Risk Intelligence data does not match expected value"

                    if exp.risk_intelligence is not None:
                        assert contains(
                            json.dumps(res.risk_intelligence_raw), "header_user_agent"
                        ), f"Test {test['name']}: Risk Intelligence raw data does not contain 'header_user_agent'"

                    if (
                        exp.risk_intelligence is not None
                        and res.risk_intelligence is not None
                    ):
                        exp_client = exp.risk_intelligence.client
                        res_client = res.risk_intelligence.client
                        if exp_client is not None and res_client is not None:
                            assert (
                                exp_client.header_user_agent
                                == res_client.header_user_agent
                            ), f"Test {test['name']}: header_user_agent does not match"

                            exp_browser = exp_client.browser
                            res_browser = res_client.browser
                            if exp_browser is not None and res_browser is not None:
                                assert (
                                    exp_browser.id == res_browser.id
                                ), f"Test {test['name']}: client.browser.id does not match"
