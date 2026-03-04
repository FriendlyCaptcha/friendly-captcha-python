import json
import os

from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates

from friendly_captcha_client.client import (
    FriendlyCaptchaClient,
    RiskIntelligenceRetrieveResult,
)

app = FastAPI()
templates = Jinja2Templates(directory="./templates/")

FRC_SITEKEY = os.getenv("FRC_SITEKEY")
FRC_APIKEY = os.getenv("FRC_APIKEY")

# Optional: "global", "eu", or a full API base endpoint like "https://eu.frcapi.com".
FRC_API_ENDPOINT = os.getenv("FRC_API_ENDPOINT")
# Optional: SDK/agent endpoint used in the browser widget.
FRC_AGENT_ENDPOINT = os.getenv("FRC_AGENT_ENDPOINT")

if not FRC_SITEKEY or not FRC_APIKEY:
    print(
        "Please set FRC_SITEKEY and FRC_APIKEY before running this example to your Friendly Captcha sitekey and API key respectively."
    )
    exit(1)

frc_client = FriendlyCaptchaClient(
    api_key=FRC_APIKEY,
    sitekey=FRC_SITEKEY,
    api_endpoint=FRC_API_ENDPOINT,
    strict=False,
)


def _render_template(request: Request, **values):
    return templates.TemplateResponse("demo.html", {"request": request, **values})


def _base_template_data():
    return {
        "message": "",
        "sitekey": FRC_SITEKEY,
        "agent_endpoint": FRC_AGENT_ENDPOINT or "",
        "risk_token": "",
        "token_timestamp": "",
        "token_expires_at": "",
        "token_num_uses": "",
        "risk_intelligence_raw": "",
    }


@app.get("/")
def read_root(request: Request):
    return _render_template(request, **_base_template_data())


@app.post("/")
def post_form(
    request: Request,
    frc_risk_intelligence_token: str = Form("", alias="frc-risk-intelligence-token"),
):
    data = _base_template_data()

    risk_token = (frc_risk_intelligence_token or "").strip()
    if not risk_token:
        data["message"] = "No risk intelligence token found."
        return _render_template(request, **data)

    data["risk_token"] = risk_token

    result: RiskIntelligenceRetrieveResult = frc_client.retrieve_risk_intelligence(
        risk_token
    )
    if not result.was_able_to_retrieve:
        data["message"] = "Risk intelligence retrieval failed: {}".format(result.error)
        return _render_template(request, **data)

    if result.data is None:
        data["message"] = (
            "Risk intelligence retrieve succeeded, but no data was returned."
        )
        return _render_template(request, **data)

    if result.data.risk_intelligence is None:
        data["message"] = (
            "Token was valid, but risk intelligence data was not returned."
        )
        data["token_timestamp"] = result.data.details.timestamp
        data["token_expires_at"] = result.data.details.expires_at
        data["token_num_uses"] = result.data.details.num_uses
        return _render_template(request, **data)

    data["message"] = "Retrieved risk intelligence data successfully."
    data["token_timestamp"] = result.data.details.timestamp
    data["token_expires_at"] = result.data.details.expires_at
    data["token_num_uses"] = result.data.details.num_uses
    data["risk_intelligence_raw"] = json.dumps(
        result.data.risk_intelligence.model_dump(by_alias=True),
        indent=2,
    )
    return _render_template(request, **data)
