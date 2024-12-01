# home-assistant-openid-auth-provider

A Home Assistant Authentication Provider that can use Open ID

This software is an unofficial custom component for Home Assistant. It is not developed, endorsed, or affiliated with the Home Assistant project. Use this software at your own risk.

While efforts have been made to ensure the security and functionality of this software, it may introduce vulnerabilities, compatibility issues, or unexpected behavior. By installing and using this software, you accept full responsibility for any outcomes or consequences.

If you have concerns about security, performance, or compatibility, please consider reviewing the code before installation and ensure it meets your standards. This software is provided "as is," without warranty of any kind.

## Usage




## Development

1. Prepare virtual environment
    ```bash
    $ uv venv
    $ source .venv/bin/activate
    $ uv pip install -r requirements_dev.txt
    ```

1. Run tests
    ```bash
    $ py.test
    ```

1. Prepare Home Assistant environment
    ```bash
    $ export PYTHONPATH="${PYTHONPATH}:${PWD}"  # Allows loading custom_components
    $ hass --script ensure_config -c config
    ```

1. Run Home Assistant

    ```bash
    $ hass -c config
    ```
