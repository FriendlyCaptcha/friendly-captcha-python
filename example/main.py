import os

from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from friendly_captcha_client.client import FriendlyCaptchaClient, FriendlyCaptchaResult

app = FastAPI()

templates = Jinja2Templates(directory="./templates/")

FRC_SITEKEY = os.getenv("FRC_SITEKEY")
FRC_APIKEY = os.getenv("FRC_APIKEY")
FRIENDLY_SERVICE_ENDPOINT = os.getenv("FRIENDLY_SERVICE_ENDPOINT")

frc_client = FriendlyCaptchaClient(
    api_key=FRC_APIKEY,
    sitekey=FRC_SITEKEY,
    # https://developer.friendlycaptcha.com/docs/api/endpoints/siteverify
    siteverify_endpoint=FRIENDLY_SERVICE_ENDPOINT + "/siteverify"
    if FRIENDLY_SERVICE_ENDPOINT
    else None,
    strict=False,
)


@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "submitted": False,
            "message": "Bots are not welcome!",
            "sitekey": FRC_SITEKEY,
            # This could be set in the HTML code as well
            "friendly_service_endpoint": FRIENDLY_SERVICE_ENDPOINT,
        },
    )


@app.post("/")
def post_form(
    request: Request,
    subject: str = Form(None),
    message: str = Form(None),
    frc_captcha_response: str = Form(..., alias="frc-captcha-response"),
):
    result: FriendlyCaptchaResult = frc_client.verify_captcha_response(
        frc_captcha_response
    )

    if not result.was_able_to_verify:
        if result.is_client_error:
            # Something is wrong with our configuration, check your API key!
            # Send yourself an alert to fix this! Your site is unprotected until you fix this
            print(
                "ERROR: Was unable to verify captcha because of a configuration error:",
                result.error,
            )
        else:
            print(result.error)

    if result.should_accept:
        return templates.TemplateResponse(
            "demo.html",
            {
                "request": request,
                "submitted": True,
                "message": "Success",
                "sitekey": FRC_SITEKEY,
                # This could be set in the HTML code as well
                "friendly_service_endpoint": FRIENDLY_SERVICE_ENDPOINT,
            },
        )

    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "submitted": True,
            "message": "Failed to verify",
            "sitekey": FRC_SITEKEY,
            # This could be set in the HTML code as well
            "friendly_service_endpoint": FRIENDLY_SERVICE_ENDPOINT,
        },
    )
