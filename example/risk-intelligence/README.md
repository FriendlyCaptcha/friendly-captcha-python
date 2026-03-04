# Friendly Captcha Python Risk Intelligence Example

This example demonstrates server-side risk intelligence retrieval with `retrieve_risk_intelligence`.

### Requirements

- Python 3.9+
- Your Friendly Captcha API key and sitekey.

### Start the application

- Set up a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

- Set environment variables and start the application

> NOTE: `FRC_API_ENDPOINT` and `FRC_AGENT_ENDPOINT` are optional. If not set, default values are used. You can also use `global` or `eu` as shorthands.

```bash
FRC_APIKEY=<your API key> \
FRC_SITEKEY=<your sitekey> \
FRC_API_ENDPOINT=<api endpoint> \
FRC_AGENT_ENDPOINT=<agent endpoint> \
uvicorn main:app --reload --port 8000
```

## Usage

Navigate to http://localhost:8000/ in your browser.
The token generation starts automatically. Submit the form to retrieve the risk intelligence data server-side.
Tokens are cached in the browser for the duration of their validity period so refreshing the page does not regenerate the token.
You can regenerate the token by clicking the "Regenerate Token" button.
