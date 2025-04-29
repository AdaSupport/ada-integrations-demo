# Ada Knowledge Base Integration Demo

This is an example Knowledge integration. Learn how to take a third-party knowledge base, _Cool Shop Knowledge Hub_, and create an Ada Platform integration to sync articles from the Cool Shop Knowledge Hub to Ada's AI Agent.

This code covers the following aspects of building an integration:

- Setting up an integration server to handle OAuth callbacks from Ada, refresh tokens for Ada API access, and complete an installation flow to an Ada instance
- Register the integration with Ada, including required Ada API scopes and any configuration details needed to connect the third party system (e.g. Cool Shop Knowledge Hub) with Ada
- Handle installations from an Ada instance

## Prerequisites

- Python 3.12
- Make
- A tool to expose your local server to the internet (ngrok)
- Ada Platform account with appropriate permissions

## Quick Start

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ada-integrations-demo
   ```

2. Configure your environment variables:
   ```bash
   make setup-env
   ```
   Then edit the `.env` file with your specific configuration values.

3. Set up the environment and install dependencies:
   ```bash
   make build
   ```

4. Start a tunnel to your local server using ngrok (or your preferred tool):
   ```bash
   ngrok http <APP_PORT> --url <YOUR_TUNNEL_URL>
   ```

5. Create a Platform Integration:
   - Go to your Ada dashboard > Platform > APIs and create a new API key
   - Use the API key to create a new platform integration with the following details:
     - Name: Your integration name
     - Description: Description of your integration
     - Uninstallation URL: `https://<YOUR_TUNNEL_URL>/uninstall`
     - OAuth Callback URL: `https://<YOUR_TUNNEL_URL>/oauth/callback`
     - Scopes: `articles:read`, `knowledge_sources:write`
   - Note the integration ID and client secret
    <details>
    <summary>Create a new platform integration using the following v2 API</summary>

    > [!IMPORTANT]
    > Update the `uninstallation_url` and `oauth_callback_url` accordingly

    > [!TIP]
    > The contents of `configuration_fields` in the request body can be any valid json schema

    ```
    [POST] /v2/platform-integrations

    Headers:
    Authorization: Bearer <plat_api_key>
    Content-Type: application/json

    Body:
    {
        "name": "Cool Shop Knowledge Hub",
        "description": "Power your AI Agent with Cool Shop Knowledge Hub",
        "author": "Ada",
        "contact": "developer-partnerships@ada.support",
        "uninstallation_url": "https://<YOUR_TUNNEL_URL>/uninstall",
        "oauth_callback_url": "https://<YOUR_TUNNEL_URL>/oauth/authorize",
        "tags": [
            "knowledge"
        ],
        "scopes": [
            "articles:read",
            "knowledge_sources:write"
        ],
        "configuration_fields": {
            "title": "Connect to Cool Shop Knowledge Hub",
            "required": [
                "credentials"
            ],
            "properties": {
                "credentials": {
                    "properties": {
                        "installation_name": {
                            "type": "string",
                            "title": "Cool Shop Knowledge Hub",
                            "description": "How your installation will appear in Ada"
                        }
                    },
                    "required": [
                        "installation_name"
                    ]
                }
            }
        },
        "identifier_field_path": "credentials.installation_name"
    }
    ```
    </details>



6. Update your `.env` file with the integration details:
   ```
   ADA_INTEGRATION_ID=your_integration_id
   ADA_INTEGRATION_SECRET=your_client_secret
   ADA_CREATOR_BOT_HANDLE=your_bot_handle
   ```

7. Start the application:
   ```bash
   make run
   ```

8. In your web browser navigate to `https://<ADA_CREATOR_BOT_HANDLE>.ada.support/platform/integrations/<ADA_INTEGRATION_ID>`

9. You should now see your integration; click Connect and complete the setup

## Available Make Commands

- `make build`: Sets up the Python virtual environment and installs dependencies
- `make run`: Starts the application
- `make clean`: Cleans up generated files and virtual environment
- `make setup-env`: Creates .env file from .env.example if it doesn't exist

## Support

For questions or support, please email developer-partnerships@ada.support

> [!IMPORTANT]
> This code is for example use only, and modifications may be needed to run this code. Additionally, pull requests and/or issues for this repository will not be monitored.

## Additional Resources

For more documentation and context about Ada integrations, visit the [Ada Integrations API documentation](https://developers.ada.cx/reference/integrations/overview).
