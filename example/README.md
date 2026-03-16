# Friendly Captcha FastAPI Example

This application integrates Friendly Captcha for form submissions using FastAPI.
It verifies captcha responses and retrieves risk intelligence (if enabled on the application) from the same form flow.

### Requirements

- Python 3.10+
- Your Friendly Captcha API key and sitekey.

### Start the application

- Set up a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

- Set environment variables and start the application

> NOTE: `FRC_API_ENDPOINT` and `FRC_WIDGET_ENDPOINT` are optional. If not set, default values are used. You can also use `global` or `eu` as shorthands for both.
> For the frontend `data-api-endpoint`, use the base endpoint (for example `http://localhost:8182`), not `/api/v2/captcha`.

```bash
FRC_APIKEY=<your API key> FRC_SITEKEY=<your sitekey> FRC_API_ENDPOINT=<api endpoint> FRC_WIDGET_ENDPOINT=<widget endpoint> uvicorn main:app --reload --port 8000
```

## Usage

Navigate to http://localhost:8000/ in your browser.
Fill out the form and submit. The backend verifies the captcha and also retrieves risk intelligence data when a risk intelligence token is available.
