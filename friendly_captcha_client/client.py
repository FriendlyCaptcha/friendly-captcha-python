from typing import Union
import logging

import requests
from pydantic import ValidationError

from friendly_captcha_client.schemas import (
    DefaultErrorCodes,
    FriendlyCaptchaResponse,
    FriendlyCaptchaResult,
    Error,
    NON_STRICT_ERROR_CODES,
    DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE,
)

GLOBAL_SITEVERIFY_ENDPOINT = "https://global.frcapi.com/api/v2/captcha/siteverify"
EU_SITEVERIFY_ENDPOINT = "https://eu.frcapi.com/api/v2/captcha/siteverify"

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


class FriendlyCaptchaClient:
    def __init__(
        self,
        api_key: str,
        sitekey: str,
        siteverify_endpoint: str = None,
        strict=False,
        verbose=False,
    ):
        self.api_key = api_key
        self.sitekey = sitekey
        self.strict = strict
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose

        if siteverify_endpoint is None or siteverify_endpoint == "global":
            siteverify_endpoint = GLOBAL_SITEVERIFY_ENDPOINT
        elif siteverify_endpoint == "eu":
            siteverify_endpoint = EU_SITEVERIFY_ENDPOINT
        self.siteverify_endpoint = siteverify_endpoint

        self._non_strict_error_code = [
            DefaultErrorCodes.AUTH_REQUIRED,
            DefaultErrorCodes.AUTH_INVALID,
            DefaultErrorCodes.SITEKEY_INVALID,
            DefaultErrorCodes.RESPONSE_MISSING,
            DefaultErrorCodes.BAD_REQUEST,
            DefaultErrorCodes.CLIENT_ERROR,
        ]

        self._strict_error_code = [
            DefaultErrorCodes.RESPONSE_INVALID,
            DefaultErrorCodes.RESPONSE_TIMEOUT,
            DefaultErrorCodes.RESPONSE_DUPLICATE,
        ]

    @staticmethod
    def _create_friendly_response_with_error(raw_response, default_error_detail):
        if not isinstance(raw_response, dict):
            raw_response = {}
            error_code = "decode_response_failed"
        else:
            error_code = raw_response.get("error", {}).get("error_code")

        error_detail = raw_response.get("error", {}).get(
            "details", str(default_error_detail)
        )
        return FriendlyCaptchaResponse(
            success=raw_response.get("success", False),
            error=Error(
                error_code=error_code if error_code else "",
                detail=error_detail if error_detail else str(default_error_detail),
            ),
        )

    @staticmethod
    def _is_client_error(error: Union[Error, None]):
        return (
            error is not None and error.error_code in NON_STRICT_ERROR_CODES
        )  # TODO: this could be O(1)

    @staticmethod
    def _get_current_version():
        my_version = "0.0.0"
        try:
            import pkg_resources

            my_version = pkg_resources.get_distribution(
                "friendly-captcha-client"
            ).version
        except Exception:
            pass
        return my_version

    def _process_response(self, response) -> (FriendlyCaptchaResponse, int):
        """Process the API response and validate its structure.

        Args:
            response (requests.Response): The API response.

        Returns:
            tuple: A tuple containing the FriendlyResponse object and the status code.
        """
        try:
            friendly_response = FriendlyCaptchaResponse.model_validate(response.json())
        except ValidationError as e:
            if self.verbose:
                self.logger.error("Error in validating friendly response: %s", e)
            friendly_response = self._create_friendly_response_with_error(
                response.json(), e
            )

        except Exception as e:
            if self.verbose:
                self.logger.error("Error parsing friendly response: %s", e)
            friendly_response = self._create_friendly_response_with_error(
                response.json(), e
            )
        return friendly_response, response.status_code

    def _is_loose_verification_available(
        self, status_code: int, error: Union[Error, None]
    ):
        """Check if loose verification is available based on the status code.
        If strict is false (= the default), and verification was not able to happen
        (e.g. because your API key is incorrect, or the Friendly Captcha API is down)
        then will return true regardless.

        Args:
            status_code (int): The HTTP status code.
            error: error from the response if present
        Returns:
            bool: True if loose verification is available, False otherwise.
        """
        return error is None or (
            not self.strict and self._is_error_loose(error, status_code)
        )

    def _is_error_loose(self, error, status_code):
        # known error where we allow loose verification
        if (
            any(
                error.error_code == _error.value
                for _error in self._non_strict_error_code
            )
            or all(  # unknown errors where we allow loose verification
                error.error_code != _error.value for _error in DefaultErrorCodes
            )
            and status_code in [200, 500]
        ):
            return True
        return False

    def _handle_api_response(self, response: requests.request) -> FriendlyCaptchaResult:
        """Handle the API response and determine the success status.

        Args:
            response (requests.Response): The API response.

        Returns:
            FriendlyCaptchaResult: The processed result from the API response.
        """
        friendly_response, status_code = self._process_response(response)

        was_able_to_verify = status_code == 200

        if was_able_to_verify and friendly_response.error is not None:
            if (
                friendly_response.error.error_code
                == DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE
            ):
                was_able_to_verify = False

            # and not ((friendly_response.error is None) and friendly_response.error.error_code != "unknown_error_code")

        friendly_result = FriendlyCaptchaResult(
            should_accept=self._is_loose_verification_available(
                status_code, friendly_response.error
            ),
            was_able_to_verify=was_able_to_verify,
            is_client_error=self._is_client_error(friendly_response.error),
            data=friendly_response.data,
            error=friendly_response.error,
        )

        return friendly_result

    def verify_captcha_response(
        self, captcha_response: str, timeout: int = 10
    ) -> FriendlyCaptchaResult:
        """Verify the captcha response using the FriendlyCaptcha API.

        Refer to the official documentation for more details:
        https://developer.friendlycaptcha.com/docs/api/endpoints/siteverify

        Args:
            captcha_response (str): The captcha response to verify.
            timeout (int, optional): The request timeout in seconds. Defaults to 10.

        Returns:
             FriendlyCaptchaResult: The processed result from the API response.
        """
        if not isinstance(captcha_response, str):
            return FriendlyCaptchaResult(
                should_accept=False,
                was_able_to_verify=True,
            )

        response = requests.post(
            url=self.siteverify_endpoint,
            json={"response": captcha_response, "sitekey": self.sitekey},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Api-Key": self.api_key,
                "Frc-Sdk": f"friendly-captcha-python@{self._get_current_version()}",
            },
            timeout=timeout,
        )
        return self._handle_api_response(response)
