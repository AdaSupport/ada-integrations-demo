import base64
from datetime import UTC, datetime, timedelta
import hashlib
from hmac import HMAC
import logging
from flask import Flask, redirect, render_template, request
import requests

from config import Config
from kb_integration_demo import database


logger = logging.getLogger(__name__)
app = Flask("kb-integration-demo", template_folder="./kb_integration_demo/templates")

BASE_URL_TEMPLATE = "https://{}.ada.support"


@app.route("/")
def hello():
    return "Hello, World!"


@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    """Handles completion of the OAuth flow with Ada

    As part of this you will want to:
    - Exchange the authorization code for access and refresh tokens
    - Store tokens, as well as installation details
    - Redirect to your confirmation page for connecting to the Knowledge Hub
    """
    referer_url = request.headers.get("Referer")
    code = request.args.get("code")
    integrator_base_url = BASE_URL_TEMPLATE.format(Config.creator_bot_handle)

    # Exchange code for access and refresh tokens
    token_url = f"{integrator_base_url}/api/platform_integrations/oauth/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "client_id": Config.integration_id,
        "client_secret": Config.integration_secret,
        "code": code,
        "grant_type": "authorization_code",
    }
    token_response = requests.post(token_url, headers=headers, data=payload)

    if token_response.status_code != 200:
        logger.warning(
            "failed to exchange code for tokens",
            extra={"status_code": token_response.status_code},
        )
        return _redirect_to_ada_error(referer_url, Config.integration_id)

    token_data = token_response.json()
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]
    expiry_ts = datetime.now(UTC) + timedelta(token_data["expires_in"])
    installation_secret = token_data["client_secret"]

    # Get installation-specific details tied to the access token
    fetch_self_url = f"{integrator_base_url}/api/platform_integrations/oauth/self"
    headers = {"Authorization": f"Bearer {access_token}"}
    fetch_self_response = requests.get(fetch_self_url, headers=headers)

    if fetch_self_response.status_code != 200:
        logger.warning(
            "failed to get installation details",
            extra={"status_code": fetch_self_response.status_code},
        )
        return _redirect_to_ada_error(referer_url, Config.integration_id)

    fetch_self_data = fetch_self_response.json()
    installation_id = fetch_self_data["platform_integration_installation_id"]
    installer_bot_handle = fetch_self_data["client_handle"]

    database.insert_installation(
        installation_id,
        access_token,
        refresh_token,
        expiry_ts,
        installation_secret,
        installer_bot_handle,
    )

    installer_base_url = BASE_URL_TEMPLATE.format(installer_bot_handle)

    return render_template(
        "oauth_authorize.html",
        installation_id=installation_id,
        integration_id=Config.integration_id,
        installer_base_url=installer_base_url,
    )


@app.route("/oauth/complete", methods=["GET"])
def oauth_complete():
    """Called when the Ada user approves connection to the Knowledge Hub

    As part of this you will want to:
    - Update the installation's status to "complete" if all setup is complete
    - Pull data (e.g. articles) from the Cool Shop Knowledge Hub that you would like to replicate in Ada
    - Redirect to Ada's connection success page
    """
    installation_id = request.args.get("installation-id")
    installation = database.get_installation(installation_id)
    installer_base_url = BASE_URL_TEMPLATE.format(installation.installer_bot_handle)

    # Update installation status to "complete"
    installation_update_url = f"{installer_base_url}/api/v2/platform-integrations/{Config.integration_id}/installations/{installation_id}"
    headers = {"Authorization": f"Bearer {installation.access_token}"}
    payload = {"status": "complete"}
    installation_update_response = requests.patch(installation_update_url, headers=headers, json=payload)
    if installation_update_response.status_code != 200:
        logger.warning(
            "failed to update installation status",
            extra={"status_code": installation_update_response.status_code},
        )
        return _redirect_to_ada_error(installer_base_url, Config.integration_id)

    # Create a new Knowledge Source
    # requires knowledge_sources:write scope
    knowledge_source_url = f"{installer_base_url}/api/v2/knowledge/sources"
    headers = {"Authorization": f"Bearer {installation.access_token}"}
    payload = {
        "id": f"cool-shop-knowledge-hub-{installation_id}",
        "name": f"Cool Shop Knowledge Hub",
    }
    knowledge_source_response = requests.post(
        knowledge_source_url, headers=headers, json=payload
    )
    if knowledge_source_response.status_code != 200:
        logger.warning(
            "failed to create knowledge source",
            extra={"status_code": knowledge_source_response.status_code},
        )
        return _redirect_to_ada_error(installer_base_url, Config.integration_id)

    # Bulk import knowledge articles from the Knowledge Hub to Ada
    # requires articles:write scope
    knowledge_articles_url = f"{installer_base_url}/api/v2/knowledge/bulk/articles"
    headers = {"Authorization": f"Bearer {installation.access_token}"}
    payload = [
        {
            "id": f"kb-integration-demo-article-{installation_id}",
            "knowledge_source_id": f"kb-integration-demo-{installation_id}",
            "name": "Article Title",
            "content": "Article Content",
        }
    ]
    knowledge_articles_response = requests.post(knowledge_articles_url, headers=headers, json=payload)
    if knowledge_articles_response.status_code != 200:
        logger.warning(
            "failed to bulk import knowledge articles",
            extra={"status_code": knowledge_articles_response.status_code},
        )
        return _redirect_to_ada_error(installer_base_url, Config.integration_id)

    return _redirect_to_ada_success(installer_base_url, Config.integration_id)


@app.route("/uninstall", methods=["DELETE"])
def uninstall():
    """Called when a Ada user uninstalls this integration from their Ada instance
    
    As part of this you will want to:
    - verify the signature of the request to confirm it's from Ada
    - delete any data that you may have associated with this particular installation
    """
    installation_id = request.args.get("installation_id")
    installation = database.get_installation(installation_id)

    signature = request.headers.get("x-ada-signature-V2")
    timestamp = request.headers.get("x-ada-timestamp-V2")
    uninstall_url = request.base_url
    request_method = request.method.lower()
    request_body = request.get_data().decode("utf-8")

    calculated_signature = HMAC(
        key=installation.installation_secret.encode(),
        msg=f"{request_method}\n{uninstall_url}\n{request_body}\n{timestamp}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()

    encoded_signature = base64.b64encode(calculated_signature).decode("utf-8")

    if encoded_signature != signature:
        logger.warning("signature mismatch")
        return "Unauthorized", 401

    database.delete_installation(installation_id)

    return "OK", 204


def _redirect_to_ada_error(base_url, integration_id):
    return redirect(
        f"{base_url}/platform/integrations/{integration_id}/connections/error"
    )


def _redirect_to_ada_success(base_url, integration_id):
    return redirect(
        f"{base_url}/platform/integrations/{integration_id}/connections/success"
    )


def _refresh_access_token(installation):
    """Sample implementation for access token refreshing if needed"""
    if installation.expiry_ts > datetime.now(UTC):
        return installation

    integrator_base_url = BASE_URL_TEMPLATE.format(Config.creator_bot_handle)
    token_url = f"{integrator_base_url}/api/platform_integrations/oauth/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "client_id": Config.integration_id,
        "client_secret": Config.integration_secret,
        "refresh_token": installation.refresh_token,
        "grant_type": "refresh_token",
    }
    token_response = requests.post(token_url, headers=headers, data=payload)

    token_data = token_response.json()

    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]
    expiry_ts = datetime.now(UTC) + timedelta(token_data["expires_in"])

    return database.update_installation(
        installation.installation_id,
        access_token,
        refresh_token,
        expiry_ts,
        installation.installation_secret,
        installation.installer_bot_handle,
    )
