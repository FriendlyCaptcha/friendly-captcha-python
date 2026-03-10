from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, field_validator, model_validator

from friendly_captcha_client.schemas_risk_intelligence import RiskIntelligenceData

DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE = "decode_response_failed"
NON_STRICT_ERROR_CODES = [
    "auth_required",
    "auth_invalid",
    "sitekey_invalid",
    "response_missing",
    "bad_request",
    "token_missing",
    "token_expired",
    "request_failed_due_to_client_error",
    "client_error",
]


class DefaultErrorCodes(str, Enum):
    AUTH_REQUIRED = "auth_required"  # 401
    AUTH_INVALID = "auth_invalid"  # 401
    SITEKEY_INVALID = "sitekey_invalid"  # 400
    RESPONSE_MISSING = "response_missing"  # 400
    TOKEN_MISSING = "token_missing"  # 400
    TOKEN_EXPIRED = "token_expired"  # 400
    BAD_REQUEST = "bad_request"  # 400
    RESPONSE_INVALID = "response_invalid"  # 200
    RESPONSE_TIMEOUT = "response_timeout"  # 200
    RESPONSE_DUPLICATE = "response_duplicate"  # 200
    CLIENT_ERROR = "request_failed_due_to_client_error"

    @staticmethod
    def contains(value: str) -> bool:
        return value in DefaultErrorCodes._value2member_map_


class Error(BaseModel):
    error_code: str
    detail: str

    @field_validator("error_code")
    def validate_error_code(cls, v: str):
        """Validate and convert the error code to its enum representation if it exists."""
        if DefaultErrorCodes.contains(v):
            return DefaultErrorCodes(v)
        return v or DECODE_RESPONSE_FAILED_INTERNAL_ERROR_CODE

    @field_validator("detail")
    def validate_detail(cls, v: str):
        """Return the error detail or a default message if not provided."""
        return v or "Unknown error detail"


class VerifyResponseChallengeData(BaseModel):
    """Challenge is the data found in the challenge field of a VerifyResponse.

    It contains information about the challenge that was solved.
    """

    timestamp: str
    origin: str


class VerifyResponseData(BaseModel):
    """VerifyResponseData is the data found in the data field of a VerifyResponse."""

    # Unique identifier for this siteverify call.
    event_id: str
    # Information about the challenge that was solved.
    challenge: VerifyResponseChallengeData
    # Risk information about the solver of the captcha.
    # This may be None if risk intelligence is not enabled for your Friendly Captcha account.
    risk_intelligence: Optional[RiskIntelligenceData] = None
    risk_intelligence_raw: Optional[dict[str, Any]] = None


class FriendlyCaptchaResponse(BaseModel):
    success: bool
    data: Optional[VerifyResponseData] = None
    error: Optional[Error] = None

    @model_validator(mode="after")
    def check_data_or_error(self):
        if self.success and self.error:
            raise ValueError("If success is True, error should not be set.")
        if not self.success and self.data:
            raise ValueError("If success is False, data should not be set.")
        return self


class FriendlyCaptchaResult(BaseModel):
    should_accept: bool
    was_able_to_verify: bool
    data: Optional[VerifyResponseData] = None
    error: Optional[Error] = None
    is_client_error: bool = False


class RiskIntelligenceRetrieveTokenData(BaseModel):
    # Timestamp when the token was generated.
    timestamp: str
    # Timestamp when the token expires.
    expires_at: str
    # Number of times the token has been used.
    num_uses: int
    # The origin of the site where the token was generated.
    origin: str


class RiskIntelligenceRetrieveResponseData(BaseModel):
    # Unique identifier for this retrieve token call.
    event_id: str
    # Metadata about the token and retrieval operation.
    token: RiskIntelligenceRetrieveTokenData
    # Risk information extracted from the retrieve token.
    risk_intelligence: Optional[RiskIntelligenceData] = None
    risk_intelligence_raw: Optional[dict[str, Any]] = None


class RiskIntelligenceRetrieveResponse(BaseModel):
    success: bool
    data: Optional[RiskIntelligenceRetrieveResponseData] = None
    error: Optional[Error] = None

    @model_validator(mode="after")
    def check_data_or_error(self):
        if self.success and self.error:
            raise ValueError("If success is True, error should not be set.")
        if not self.success and self.data:
            raise ValueError("If success is False, data should not be set.")
        return self


class RiskIntelligenceRetrieveResult(BaseModel):
    is_valid: bool
    was_able_to_retrieve: bool
    data: Optional[RiskIntelligenceRetrieveResponseData] = None
    error: Optional[Error] = None
    is_client_error: bool = False
