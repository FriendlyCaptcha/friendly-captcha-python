import logging
from copy import deepcopy
from typing import Any, Tuple, Type, TypeVar, Union
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, ValidationError

from friendly_captcha_client.schemas import (
    FriendlyCaptchaResponse,
    FriendlyCaptchaResult,
    RiskIntelligenceRetrieveResponse,
    RiskIntelligenceRetrieveResult,
    DefaultErrorCodes,
    Error,
    DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE,
    NON_STRICT_ERROR_CODES,
)

GLOBAL_API_ENDPOINT = "https://global.frcapi.com"
EU_API_ENDPOINT = "https://eu.frcapi.com"

CAPTCHA_SITEVERIFY_PATH = "/api/v2/captcha/siteverify"
RISK_INTELLIGENCE_RETRIEVE_PATH = "/api/v2/riskIntelligence/retrieve"


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

ResponseModelT = TypeVar("ResponseModelT", bound=BaseModel)


class FriendlyCaptchaClient:
    def __init__(
        self,
        api_key: str,
        sitekey: str,
        # Deprecated: use api_endpoint instead.
        siteverify_endpoint: str = None,
        strict=False,
        verbose=False,
        api_endpoint: str = None,
    ):
        self.api_key = api_key
        self.sitekey = sitekey
        self.strict = strict
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose

        resolved_api_endpoint = self._resolve_api_endpoint(api_endpoint)

        if api_endpoint is None and siteverify_endpoint is not None:
            resolved_api_endpoint = self._deprecated_endpoint_to_api_endpoint(
                siteverify_endpoint,
                "siteverify_endpoint",
            )

        self.api_endpoint = resolved_api_endpoint.rstrip("/")

        self._non_strict_error_code = set(NON_STRICT_ERROR_CODES)

    @staticmethod
    def _resolve_api_endpoint(api_endpoint: str) -> str:
        if api_endpoint is None or api_endpoint == "global":
            return GLOBAL_API_ENDPOINT
        if api_endpoint == "eu":
            return EU_API_ENDPOINT
        if api_endpoint == "":
            raise ValueError("api_endpoint must not be empty")
        return api_endpoint.rstrip("/")

    @staticmethod
    def _deprecated_endpoint_to_api_endpoint(
        deprecated_endpoint: str, endpoint_param_name: str
    ) -> str:
        if deprecated_endpoint == "":
            raise ValueError("{} must not be empty".format(endpoint_param_name))

        if deprecated_endpoint in ("global", "eu"):
            return FriendlyCaptchaClient._resolve_api_endpoint(deprecated_endpoint)

        parsed = urlparse(deprecated_endpoint)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "invalid {} URL: expected fully qualified URL".format(
                    endpoint_param_name
                )
            )

        return "{}://{}".format(parsed.scheme, parsed.netloc)

    def _api_url(self, path: str) -> str:
        return "{}{}".format(self.api_endpoint, path)

    @property
    def siteverify_endpoint(self) -> str:
        return self._api_url(CAPTCHA_SITEVERIFY_PATH)

    @property
    def risk_intelligence_retrieve_endpoint(self) -> str:
        return self._api_url(RISK_INTELLIGENCE_RETRIEVE_PATH)

    @staticmethod
    def _create_response_with_error(
        raw_response: Any,
        default_error_detail: Exception,
        response_model: Type[ResponseModelT],
    ) -> ResponseModelT:
        if not isinstance(raw_response, dict):
            raw_response = {}

        error_payload = raw_response.get("error", {})
        error_code = error_payload.get(
            "error_code", DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE
        )
        error_detail = error_payload.get("detail", str(default_error_detail))

        return response_model(
            success=False,
            error=Error(
                error_code=error_code,
                detail=error_detail,
            ),
        )

    @staticmethod
    def _normalize_error_code(error_code: Union[str, DefaultErrorCodes]) -> str:
        if isinstance(error_code, DefaultErrorCodes):
            return error_code.value
        return str(error_code)

    def _is_client_error(self, error: Union[Error, None]):
        if error is None:
            return False
        return self._normalize_error_code(error.error_code) in NON_STRICT_ERROR_CODES

    @staticmethod
    def _get_current_version():
        my_version = "0.0.0"
        try:
            from importlib.metadata import version

            my_version = version("friendly-captcha-client")
        except Exception:
            pass
        return my_version

    def _process_response(
        self, response: requests.Response, response_model: Type[ResponseModelT]
    ) -> Tuple[ResponseModelT, int]:
        """Process and validate an API response payload.

        Args:
            response (requests.Response): The API response.
            response_model: The pydantic model used for response validation.

        Returns:
            tuple: A tuple containing the parsed response model and the status code.
        """
        raw_response: Any = {}

        try:
            raw_response = response.json()
        except Exception as e:
            if self.verbose:
                self.logger.error("Error decoding API JSON response: %s", e)
            parsed_response = self._create_response_with_error({}, e, response_model)
            return parsed_response, response.status_code

        raw_response = self._preserve_risk_intelligence_raw(raw_response)

        try:
            parsed_response = response_model.model_validate(raw_response)
        except ValidationError as e:
            if self.verbose:
                self.logger.error("Error validating API response: %s", e)
            parsed_response = self._create_response_with_error(
                raw_response, e, response_model
            )

        except Exception as e:
            if self.verbose:
                self.logger.error("Error parsing API response: %s", e)
            parsed_response = self._create_response_with_error(
                raw_response, e, response_model
            )

        return parsed_response, response.status_code

    @staticmethod
    def _preserve_risk_intelligence_raw(raw_response: Any) -> Any:
        if not isinstance(raw_response, dict):
            return raw_response

        data = raw_response.get("data")
        if not isinstance(data, dict):
            return raw_response

        risk_intelligence = data.get("risk_intelligence")
        if isinstance(risk_intelligence, dict):
            data["risk_intelligence_raw"] = deepcopy(risk_intelligence)

        return raw_response

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
        error_code = self._normalize_error_code(error.error_code)

        # known error where we allow loose verification
        if (
            error_code in self._non_strict_error_code
            or all(  # unknown errors where we allow loose verification
                error_code != _error.value for _error in DefaultErrorCodes
            )
            and status_code in [200, 500]
        ):
            return True
        return False

    @staticmethod
    def _is_decode_response_failed(error: Union[Error, None]) -> bool:
        return (
            error is not None
            and FriendlyCaptchaClient._normalize_error_code(error.error_code)
            == DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE
        )

    def _handle_verify_captcha_response(
        self, response: requests.request
    ) -> FriendlyCaptchaResult:
        """Handle the verify captcha API response and determine the success status.

        Args:
            response (requests.Response): The API response.

        Returns:
            FriendlyCaptchaResult: The processed result from the API response.
        """
        friendly_response, status_code = self._process_response(
            response, FriendlyCaptchaResponse
        )

        was_able_to_verify = status_code == 200

        if was_able_to_verify and self._is_decode_response_failed(
            friendly_response.error
        ):
            was_able_to_verify = False

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

    def _handle_risk_intelligence_retrieve_response(
        self, response: requests.request
    ) -> RiskIntelligenceRetrieveResult:
        """Handle the risk intelligence retrieve API response and determine the success status.

        Args:
            response (requests.Response): The API response.

        Returns:
            RiskIntelligenceRetrieveResult: The processed result from the API response.
        """
        retrieve_response, status_code = self._process_response(
            response, RiskIntelligenceRetrieveResponse
        )

        decode_response_failed = self._is_decode_response_failed(
            retrieve_response.error
        )
        was_able_to_retrieve = status_code == 200 and not decode_response_failed

        return RiskIntelligenceRetrieveResult(
            is_valid=was_able_to_retrieve and retrieve_response.success,
            was_able_to_retrieve=was_able_to_retrieve,
            is_client_error=(status_code != 200 and not decode_response_failed),
            data=retrieve_response.data,
            error=retrieve_response.error,
        )

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
        return self._handle_verify_captcha_response(response)

    def retrieve_risk_intelligence(
        self, token: str, timeout: int = 10
    ) -> RiskIntelligenceRetrieveResult:
        """Retrieve risk intelligence data for a risk intelligence token.

        Refer to the official documentation for more details:
        https://developer.friendlycaptcha.com/docs/api/endpoints/risk-intelligence-retrieve

        Args:
            token (str): The risk intelligence token to retrieve.
            timeout (int, optional): The request timeout in seconds. Defaults to 10.

        Returns:
             RiskIntelligenceRetrieveResult: The processed result from the API response.
        """
        if not isinstance(token, str):
            return RiskIntelligenceRetrieveResult(
                was_able_to_retrieve=False,
            )

        print(f"friendly-captcha-python@{self._get_current_version()}")

        response = requests.post(
            url=self.risk_intelligence_retrieve_endpoint,
            json={"token": token, "sitekey": self.sitekey},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Api-Key": self.api_key,
                "Frc-Sdk": f"friendly-captcha-python@{self._get_current_version()}",
            },
            timeout=timeout,
        )
        return self._handle_risk_intelligence_retrieve_response(response)
