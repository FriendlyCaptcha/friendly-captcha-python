# Friendly Captcha FastAPI Example

This application integrates Friendly Captcha for form submissions using FastAPI.

### Requirements

- Python 3.9+
- Your Friendly Captcha API key and sitekey.

### Start the application

- Clone the repository:

```bash
git clone <repository_url>
cd <repository_directory>
```

- Set up a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

- Setup env variables and start the application

> NOTE: `FRC_SITEVERIFY_ENDPOINT` and `FRC_WIDGET_ENDPOINT` are optional. If not set, the default values will be used. You can also use `global` or `eu` as shorthands for both.

```bash
FRC_APIKEY=<your API key> FRC_SITEKEY=<your sitekey> FRC_SITEVERIFY_ENDPOINT=<siteverify endpoint> FRC_WIDGET_ENDPOINT=<widget endpoint> uvicorn main:app --reload --port 8000
```

# Usage

Navigate to http://localhost:8000/ in your browser.
Fill out the form and submit. The Friendly Captcha verification will protect the form from bots.
