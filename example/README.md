# Friendly Captcha FastAPI Example
This application integrates Friendly Captcha for form submissions using FastAPI.

### Requirements
- Python 3.9+
- FastAPI
- FRC_APIKEY: Your Friendly Captcha API key.
- FRC_SITEKEY: Your Friendly Captcha site key.

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

- Setup env variable and start the application
- Options for the siteverify endpoints:
  - GLOBAL_FRIENDLY_SERVICE_ENDPOINT_URL = "https://global.frcapi.com/api/v2/captcha"
  - EU_FRIENDLY_SERVICE_ENDPOINT_URL = "https://eu.frcapi.com/api/v2/captcha"
  - LOCAL_FRIENDLY_SERVICE_ENDPOINT_URL = "http://localhost:8182/api/v2/captcha"

```bash 
FRC_APIKEY=<your api key> FRC_SITEKEY=<your site key> FRIENDLY_SERVICE_ENDPOINT=<your siteverify endpoint> uvicorn main:app --reload --port 8000
```

# Usage
Navigate to http://localhost:8000/ in your browser.
Fill out the form and submit. The Friendly Captcha verification will ensure that the form submission is from a human.