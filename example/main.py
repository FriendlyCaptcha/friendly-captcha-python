import os

from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from friendly_captcha_client.client import FriendlyCaptchaClient, FriendlyCaptchaResult

app = FastAPI()

templates = Jinja2Templates(directory="./templates/")

FRC_SITEKEY = os.getenv("FRC_SITEKEY")
FRC_APIKEY = os.getenv("FRC_APIKEY")

# Optionally we can pass in custom endpoints to be used, such as "eu".
FRC_SITEVERIFY_ENDPOINT = os.getenv("FRC_SITEVERIFY_ENDPOINT")
FRC_WIDGET_ENDPOINT = os.getenv("FRC_WIDGET_ENDPOINT")

if not FRC_SITEKEY or not FRC_APIKEY:
    print(
        "Please set the FRC_SITEKEY and FRC_APIKEY environment values before running this example to your Friendly Captcha sitekey and API key respectively."
    )
    exit(1)

frc_client = FriendlyCaptchaClient(
    api_key=FRC_APIKEY,
    sitekey=FRC_SITEKEY,
    siteverify_endpoint=FRC_SITEVERIFY_ENDPOINT,  # Optional, defaults to "global"
    strict=False,
)


@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "message": "",
            "sitekey": FRC_SITEKEY,
            "widget_endpoint": FRC_WIDGET_ENDPOINT,
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
        # In this case we were not actually able to verify the response embedded in the form, but we may still want to accept it.
        # It could mean there is a network issue or that the service is down. In those cases you generally want to accept submissions anyhow
        # That's why we use `shouldAccept()` below to actually accept or reject the form submission. It will return true in these cases.

        if result.is_client_error:
            # Something is wrong with our configuration, check your API key!
            # Send yourself an alert to fix this! Your site is unprotected until you fix this.
            print("CAPTCHA CONFIG ERROR: ", result.error)
        else:
            print("Failed to verify captcha response: ", result.error)

    if not result.should_accept:
        return templates.TemplateResponse(
            "demo.html",
            {
                "request": request,
                "message": "❌ Anti-robot check failed, please try again.",
                "sitekey": FRC_SITEKEY,
                "widget_endpoint": FRC_WIDGET_ENDPOINT,
            },
        )

    # The captcha was OK, process the form.
    subject, message  # Normally we would use the form data here and submit it to our database.

    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "message": "✅ Your message has been submitted successfully.",
            "sitekey": FRC_SITEKEY,
            "widget_endpoint": FRC_WIDGET_ENDPOINT,
        },
    )
