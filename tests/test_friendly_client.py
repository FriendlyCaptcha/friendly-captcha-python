from unittest.mock import Mock, patch

import pytest
import requests_mock

from friendly_captcha_client.client import DefaultErrorCodes, FriendlyCaptchaResult

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


def test_shorthand_siteverify_endpoint():
    from friendly_captcha_client.client import FriendlyCaptchaClient

    # test default
    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
    )

    assert (
        client.siteverify_endpoint
        == "https://global.frcapi.com/api/v2/captcha/siteverify"
    )

    # test 'eu' shorthand
    client = FriendlyCaptchaClient(
        api_key="FRC_APIKEY",
        sitekey="FRC_SITE_KEY",
        siteverify_endpoint="eu",
    )

    assert (
        client.siteverify_endpoint == "https://eu.frcapi.com/api/v2/captcha/siteverify"
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
