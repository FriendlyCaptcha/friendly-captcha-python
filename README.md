# Friendly Captcha Python SDK

A Python client for the [Friendly Captcha](https://friendlycaptcha.com) service. This client allows for easy integration and verification of captcha responses with the Friendly Captcha API.

> This library is for [Friendly Captcha V2](https://developer.friendlycaptcha.com) only. If you are looking for V1, look [here](https://docs.friendlycaptcha.com)

## Installation

```bash
pip install friendly-captcha-client
```

## Usage

Below are some basic examples of how to use the client.

For a more detailed example, take a look at the [example](./example) directory.

### Initialization

To start using the client:

```python
from friendly_client import FriendlyCaptchaClient

client = FriendlyCaptchaClient(
    api_key="YOUR_API_KEY",
    sitekey="YOUR_SITEKEY"
)
```

### Verifying a Captcha Response

After calling `verify_captcha_response` with the captcha response there are two functions on the result object that you should check:

- `was_able_to_verify` indicates whether we were able to verify the captcha response. This will be `False` in case there was an issue with the network/our service or if there was a mistake in the configuration.
- `should_accept` indicates whether the captcha response was correct. If the client is running in non-strict mode (default) and `was_able_to_verify` returned `False`, this will be `True`.

Below are some examples of this behaviour.

#### Verifying a correct captcha response without issues when veryfing:

```python
result = client.verify_captcha_response("CORRECT?CAPTCHA_RESPONSE_HERE")
print(result.was_able_to_verify) # True
print(result.should_accept) # True
```

#### Verifying an incorrect captcha response without issues when veryfing:

```python
result = client.verify_captcha_response("INCORRECT_CAPTCHA_RESPONSE_HERE")
print(result.was_able_to_verify) # True
print(result.should_accept) # False
```

#### Verifying an incorrect captcha response with issues (network issues or bad configuration) when veryfing in non-strict mode (default):

```python
result = client.verify_captcha_response("INCORRECT_CAPTCHA_RESPONSE_HERE")
print(result.was_able_to_verify) # False
print(result.should_accept) # True
```

#### Verifying an incorrect captcha response with issues (network/service issues or bad configuration) when veryfing in strict mode:

```python
client.strict = True
result = client.verify_captcha_response("INCORRECT_CAPTCHA_RESPONSE_HERE")
print(result.should_accept)  # False
print(result.was_able_to_verify)  # False
```

### Configuration

The client offers several configuration options:

- **api_key**: Your Friendly Captcha API key.
- **sitekey**: Your Friendly Captcha sitekey.
- **strict**: (Optional) In case the client was not able to verify the captcha response at all (for example if there is a network failure or a mistake in configuration), by default the `verify_captcha_response` returns `True` regardless. By passing `strict=True`, it will return `False` instead: every response needs to be strictly verified.
- **siteverify_endpoint**: (Optional) The endpoint URL for the site verification API. Shorthands `eu` or `global` are also accepted. Default is `global`.
- **verbose**: (Optional) Default is False. Turn on basic logging.
- Error Handling: The client has built-in error handling mechanisms. In case of unexpected responses or errors from the Friendly Captcha API, the client will log the error and provide a default response.

## Development

To install it locally:

```bash
pip install -e .
pip install -r requirements-dev.txt
```

Run the tests:

```bash
# Run the unit tests
python -m pytest

# Run the SDK integration tests (requires that you have the SDK test mock server running)
docker run -p 1090:1090 friendlycaptcha/sdk-testserver:latest
python -m pytest integration_tests
```

## License

Open source under [MIT](./LICENSE).
