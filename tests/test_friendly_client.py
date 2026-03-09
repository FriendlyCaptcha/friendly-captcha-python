from unittest.mock import Mock, patch

import pytest
import requests_mock

from friendly_captcha_client.client import (
    DefaultErrorCodes,
    FriendlyCaptchaResult,
    RiskIntelligenceRetrieveResult,
)

# Mocked responses for different scenarios
CAPTCHA_RESPONSE = "test_captcha_response"
UNENCODABLE_CAPTCHA_RESPONSE = lambda x: x
SIMPLY_UNKNOWN_ERROR = {
    "success": False,
    "error": {
        "error_code": "some unknown error",
        "detail": "You forgot to set the X-API-Key header.",
    },
}

EMPTY_SIMPLY_BAD_RESPONSE = ""

# Mocked API responses for each error code
MOCK_RESPONSES = {
    DefaultErrorCodes.AUTH_REQUIRED: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.AUTH_REQUIRED}},
        401,
    ),
    DefaultErrorCodes.AUTH_INVALID: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.AUTH_INVALID}},
        401,
    ),
    DefaultErrorCodes.SITEKEY_INVALID: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.SITEKEY_INVALID}},
        400,
    ),
    DefaultErrorCodes.RESPONSE_MISSING: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.RESPONSE_MISSING}},
        400,
    ),
    DefaultErrorCodes.BAD_REQUEST: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.BAD_REQUEST}},
        400,
    ),
    DefaultErrorCodes.RESPONSE_INVALID: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.RESPONSE_INVALID}},
        200,
    ),
    DefaultErrorCodes.RESPONSE_TIMEOUT: (
        {"success": False, "error": {"error_code": DefaultErrorCodes.RESPONSE_TIMEOUT}},
        200,
    ),
    DefaultErrorCodes.RESPONSE_DUPLICATE: (
        {
            "success": False,
            "error": {"error_code": DefaultErrorCodes.RESPONSE_DUPLICATE},
        },
        200,
    ),
}


def test_default_api_endpoint():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
    )
    assert client.api_endpoint == "https://global.frcapi.com"
    assert (
        client.siteverify_endpoint
        == "https://global.frcapi.com/api/v2/captcha/siteverify"
    )
    assert (
        client.risk_intelligence_retrieve_endpoint
        == "https://global.frcapi.com/api/v2/riskIntelligence/retrieve"
    )


def test_shorthand_api_endpoint():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
        api_endpoint="eu",
    )

    assert client.api_endpoint == "https://eu.frcapi.com"
    assert (
        client.siteverify_endpoint == "https://eu.frcapi.com/api/v2/captcha/siteverify"
    )
    assert (
        client.risk_intelligence_retrieve_endpoint
        == "https://eu.frcapi.com/api/v2/riskIntelligence/retrieve"
    )


def test_api_endpoint_must_not_be_empty():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    with pytest.raises(ValueError, match="api_endpoint must not be empty"):
        FriendlyCaptchaClient(
            api_key="FRC_APIKEY",
            sitekey="FRC_SITE_KEY",
            api_endpoint="",
        )


def test_siteverify_endpoint_is_deprecated_shorthand():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
        siteverify_endpoint="eu",
    )

    assert client.api_endpoint == "https://eu.frcapi.com"
    assert (
        client.siteverify_endpoint == "https://eu.frcapi.com/api/v2/captcha/siteverify"
    )


def test_siteverify_endpoint_is_deprecated_and_strips_path():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
        siteverify_endpoint="https://eu.frcapi.com/api/v2/captcha/siteverify",
    )

    assert client.api_endpoint == "https://eu.frcapi.com"
    assert (
        client.siteverify_endpoint == "https://eu.frcapi.com/api/v2/captcha/siteverify"
    )
    assert (
        client.risk_intelligence_retrieve_endpoint
        == "https://eu.frcapi.com/api/v2/riskIntelligence/retrieve"
    )


def test_siteverify_endpoint_empty_is_error():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    with pytest.raises(ValueError, match="siteverify_endpoint must not be empty"):
        FriendlyCaptchaClient(
            api_key="FRC_APIKEY",
            sitekey="FRC_SITE_KEY",
            siteverify_endpoint="",
        )


def test_siteverify_endpoint_invalid_url_is_error():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    with pytest.raises(
        ValueError,
        match="invalid siteverify_endpoint URL: expected fully qualified URL",
    ):
        FriendlyCaptchaClient(
            api_key="FRC_APIKEY",
            sitekey="FRC_SITE_KEY",
            siteverify_endpoint="not-a-url",
        )


def test_api_endpoint_takes_precedence_over_deprecated_siteverify_endpoint():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
        api_endpoint="global",
        siteverify_endpoint="https://eu.frcapi.com/api/v2/captcha/siteverify",
    )

    assert client.api_endpoint == "https://global.frcapi.com"
    assert (
        client.siteverify_endpoint
        == "https://global.frcapi.com/api/v2/captcha/siteverify"
    )


# Mock the actual API post request to return the mock response
def mock_post_request(*args, **kwargs):
    json_data = kwargs["json"]
    error_code = json_data.get("response")
    if error_code in MOCK_RESPONSES:
        mock_response = Mock()
        mock_response.json.return_value = MOCK_RESPONSES[error_code][0]
        mock_response.status_code = MOCK_RESPONSES[error_code][1]
        return mock_response
    return Mock(status_code=200, json=lambda: {"success": True})


def test_verify_captcha_response_success(client):
    with requests_mock.Mocker() as m:
        m.post(client.siteverify_endpoint, json={"success": True})
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).should_accept is True
        assert (
            client.verify_captcha_response(CAPTCHA_RESPONSE).was_able_to_verify is True
        )
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).is_client_error is False


def test_verify_captcha_response_failure_with_unknown_error(client):
    with requests_mock.Mocker() as m:
        m.post(client.siteverify_endpoint, json=SIMPLY_UNKNOWN_ERROR, status_code=400)
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).should_accept is False
        assert (
            client.verify_captcha_response(CAPTCHA_RESPONSE).was_able_to_verify is False
        )
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).is_client_error is False


def test_verify_captcha_response_failure_bad_response_with_200(client):
    with requests_mock.Mocker() as m:
        m.post(
            client.siteverify_endpoint,
            json=EMPTY_SIMPLY_BAD_RESPONSE,
            status_code=200,
        )
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).should_accept is True
        assert (
            client.verify_captcha_response(CAPTCHA_RESPONSE).was_able_to_verify is False
        )
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).is_client_error is False


def test_verify_captcha_response_failure_bad_response_with_non_200(client):
    with requests_mock.Mocker() as m:
        m.post(
            client.siteverify_endpoint,
            json=EMPTY_SIMPLY_BAD_RESPONSE,
            status_code=400,
        )
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).should_accept is False
        assert (
            client.verify_captcha_response(CAPTCHA_RESPONSE).was_able_to_verify is False
        )
        assert client.verify_captcha_response(CAPTCHA_RESPONSE).is_client_error is False


def test_verify_captcha_response_failure_strict(strict_client):
    with requests_mock.Mocker() as m:
        m.post(strict_client.siteverify_endpoint, json=SIMPLY_UNKNOWN_ERROR)
        assert (
            strict_client.verify_captcha_response(CAPTCHA_RESPONSE).should_accept
            is False
        )
        assert (
            strict_client.verify_captcha_response(CAPTCHA_RESPONSE).was_able_to_verify
            is True
        )
        assert (
            strict_client.verify_captcha_response(CAPTCHA_RESPONSE).is_client_error
            is False
        )


def test_unencodable_captcha_response(client):
    assert (
        client.verify_captcha_response(UNENCODABLE_CAPTCHA_RESPONSE).should_accept
        is False
    )
    assert (
        client.verify_captcha_response(UNENCODABLE_CAPTCHA_RESPONSE).was_able_to_verify
        is True
    )
    assert (
        client.verify_captcha_response(UNENCODABLE_CAPTCHA_RESPONSE).is_client_error
        is False
    )


# Data-driven test using pytest's parametrize
@pytest.mark.parametrize(
    "error_code,expected_should_accept,expected_was_able_to_verify",
    [
        (DefaultErrorCodes.AUTH_REQUIRED, True, False),
        (DefaultErrorCodes.AUTH_INVALID, True, False),
        (DefaultErrorCodes.SITEKEY_INVALID, True, False),
        (DefaultErrorCodes.RESPONSE_MISSING, True, False),
        (DefaultErrorCodes.BAD_REQUEST, True, False),
        (DefaultErrorCodes.RESPONSE_INVALID, False, True),
        (DefaultErrorCodes.RESPONSE_TIMEOUT, False, True),
        (DefaultErrorCodes.RESPONSE_DUPLICATE, False, True),
    ],
)
def test_verify_captcha_response_errors(
    error_code, expected_should_accept, expected_was_able_to_verify, client
):
    with patch("requests.post", side_effect=mock_post_request):
        result: FriendlyCaptchaResult = client.verify_captcha_response(error_code)
        assert result.should_accept == expected_should_accept
        assert result.was_able_to_verify == expected_was_able_to_verify


# Data-driven test using pytest's parametrize
@pytest.mark.parametrize(
    "error_code,expected_should_accept,expected_was_able_to_verify",
    [
        (DefaultErrorCodes.AUTH_REQUIRED, False, False),
        (DefaultErrorCodes.AUTH_INVALID, False, False),
        (DefaultErrorCodes.SITEKEY_INVALID, False, False),
        (DefaultErrorCodes.RESPONSE_MISSING, False, False),
        (DefaultErrorCodes.BAD_REQUEST, False, False),
        (DefaultErrorCodes.RESPONSE_INVALID, False, True),
        (DefaultErrorCodes.RESPONSE_TIMEOUT, False, True),
        (DefaultErrorCodes.RESPONSE_DUPLICATE, False, True),
    ],
)
def test_verify_captcha_response_errors_strict(
    error_code, expected_should_accept, expected_was_able_to_verify, strict_client
):
    with patch("requests.post", side_effect=mock_post_request):
        result: FriendlyCaptchaResult = strict_client.verify_captcha_response(
            error_code
        )
        assert result.should_accept == expected_should_accept
        assert result.was_able_to_verify == expected_was_able_to_verify


def test_retrieve_risk_intelligence_success(client):
    retrieve_response = {
        "success": True,
        "data": {
            "event_id": "ev_1234567890",
            "risk_intelligence": {
                "network": {"ip": "127.0.0.1"},
                "client": {
                    "header_user_agent": "Mozilla/5.0",
                    "browser": {
                        "id": "chrome",
                        "name": "Chrome",
                        "version": "91.0.4472.124",
                        "release_date": "2021-06-24",
                    },
                },
            },
            "token": {
                "timestamp": "2023-08-04T13:01:25Z",
                "expires_at": "2023-08-04T13:06:25Z",
                "num_uses": 1,
                "origin": "https://example.com",
            },
        },
    }

    with requests_mock.Mocker() as m:
        m.post(
            client.risk_intelligence_retrieve_endpoint,
            json=retrieve_response,
            status_code=200,
        )

        result: RiskIntelligenceRetrieveResult = client.retrieve_risk_intelligence(
            "token"
        )
        assert result.was_able_to_retrieve is True
        assert result.is_client_error is False
        assert result.data is not None
        assert result.data.token.num_uses == 1
        assert result.data.token.origin == "https://example.com"
        assert result.data.risk_intelligence is not None
        assert (
            result.data.risk_intelligence_raw
            == retrieve_response["data"]["risk_intelligence"]
        )
        assert result.data.risk_intelligence.client is not None
        assert result.data.risk_intelligence.client.browser is not None
        assert result.data.risk_intelligence.client.browser.id == "chrome"


@pytest.mark.parametrize(
    "error_code",
    [
        DefaultErrorCodes.AUTH_REQUIRED,
        DefaultErrorCodes.AUTH_INVALID,
        DefaultErrorCodes.BAD_REQUEST,
        DefaultErrorCodes.TOKEN_MISSING,
        DefaultErrorCodes.TOKEN_EXPIRED,
    ],
)
def test_retrieve_risk_intelligence_client_errors(client, error_code):
    with requests_mock.Mocker() as m:
        m.post(
            client.risk_intelligence_retrieve_endpoint,
            json={
                "success": False,
                "error": {"error_code": error_code, "detail": ""},
            },
            status_code=400,
        )

        result: RiskIntelligenceRetrieveResult = client.retrieve_risk_intelligence(
            "token"
        )
        assert result.was_able_to_retrieve is False
        assert result.is_client_error is True


def test_retrieve_risk_intelligence_bad_response_with_500(client):
    with requests_mock.Mocker() as m:
        m.post(
            client.risk_intelligence_retrieve_endpoint,
            text="<html><body>Something went horribly wrong</body></html>",
            status_code=500,
            headers={"Content-Type": "text/html"},
        )

        result: RiskIntelligenceRetrieveResult = client.retrieve_risk_intelligence(
            "token"
        )
        assert result.was_able_to_retrieve is False
        assert result.is_client_error is False
