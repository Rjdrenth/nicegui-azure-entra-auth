import os
import uuid

import jwt
import msal
import requests
from cachetools import TTLCache
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse
from jwt.algorithms import RSAAlgorithm
from nicegui import Client, app, ui

# Load the .dotenv file
load_dotenv()

# Client ID and secret correspond to your Entra Application registration
CLIENT_ID = os.environ.get("AZURE_ENTRA_APPLICATION_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_ENTRA_APPLICATION_CLIENT_SECRET")

# Azure tenant information
TENANT_NAME = os.environ.get("AZURE_TENANT_NAME")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_NAME}"

# Scopes your application needs
SCOPE = ["User.Read"]  # Adjust as needed

# The base URL of your application. For local development "http://localhost:8080" suffices, but when deploying e.g. an
# Azure Web App, it needs to be `https://<your_app_name>.azurewebsites.net`
BASE_APPLICATION_URL = "http://localhost:8080"

# Redirect path where the user will be directed to after logging in. This needs to configured in the Entra Application
# Registration -> Manage -> Authentication -> Web Redirect URIs, prepended with the possible values for
# BASE_APPLICATION_URL, e.g.:
# - `http://localhost:8080/.auth/login/aad/callback`
# - `https://<your_app_name>.azurewebsites.net/.auth/login/aad/callback`
REDIRECT_PATH = "/.auth/login/aad/callback"

# URL to log the user out in Entra
ENTRA_LOGOUT_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_NAME}/oauth2/v2.0/logout"

# MSAL app instance
msal_app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,
)

# Cache for in-progress authorisation flows. Give the user 5 minutes to complete the flow
AUTH_FLOW_STATES = TTLCache(maxsize=256, ttl=60 * 5)

# Cache authenticated users for a maximum of 10 hours. TTL is in seconds
USER_DATA = TTLCache(maxsize=256, ttl=60 * 60 * 10)


@ui.page("/")
def index(client: Client):
    """
    This home page serves to check whether a user is logged in or not. If not, a login button will be presented. If yes,
    the user will be directed to the portal app.
    """

    # Obtain the browser ID and use it to determine whether the user is logged in or not
    browser_id = app.storage.browser["id"]
    user = USER_DATA.get(browser_id, None)

    # if "user" was not initialised
    if not user:
        # Display log in components
        with ui.column().classes("w-full items-center"):
            ui.markdown(f"## NiceGUI Entra authentication app\n Welcome to this app. Please log in").style(
                "white-space: pre-wrap"
            )

            ui.button("Login with Microsoft", on_click=lambda: ui.navigate.to("/login"))
    else:
        # If the user is logged in, store their information and redirect them to the actual app
        app.storage.user["user"] = user
        ui.navigate.to("/actual_app")


@ui.page("/login")
def login():
    """
    This page merely starts the authentication flow and then redirects the user to log in on Microsoft's website.
    Nothing is displayed to the user.
    """

    # Start the authentication flow by contacting Entra
    auth_flow = msal_app.initiate_auth_code_flow(
        SCOPE,
        redirect_uri=f"{BASE_APPLICATION_URL}{REDIRECT_PATH}",
    )

    # Keep track of the auth_flow information as received from Entra
    browser_id = app.storage.browser["id"]
    AUTH_FLOW_STATES[browser_id] = auth_flow

    # And redirect the user to the Entra login page
    return RedirectResponse(auth_flow["auth_uri"])


def _get_tenant_public_key_for_key_id(key_id, tenant_name):
    jwks_url = f"https://login.microsoftonline.com/{tenant_name}/discovery/v2.0/keys"
    response = requests.get(jwks_url)
    jwks = response.json()

    # Find the correct key from the available keys
    key = next((key for key in jwks["keys"] if key["kid"] == key_id), None)

    # Attempt to extract the actual public key
    if key:
        public_key = RSAAlgorithm.from_jwk(key)
    else:
        raise Exception("Public key not found")

    return public_key


def validate_token(jwt_token, tenant_name):
    """Validate the JWT token using the public key from Azure AD."""

    # Obtain relevant specifications from the JWT token
    header = jwt.get_unverified_header(jwt_token)
    algorithm = header["alg"]
    key_id = header["kid"]

    # Obtain the Azure public key corresponding to our tenant and the given `key_id`.
    tenant_public_key = _get_tenant_public_key_for_key_id(key_id, tenant_name)

    try:
        # Decode the token, verifying the signature and claims
        decoded_token = jwt.decode(jwt_token, tenant_public_key, algorithms=[algorithm], audience=CLIENT_ID)
        return decoded_token
    except jwt.PyJWTError as e:
        print(f"Token validation error: {e}")
        return None


@ui.page(REDIRECT_PATH)
def authorized(client: Client):
    """
    After the user logged in at Microsoft, they end up back here. We verify whether the user was successful in logging
    in. If so, we perform some bookkeeping regarding user data. Nothing is displayed to the user.
    """

    # Obtain the auth_flow we previously stored for this browser and check whether the `state` in there is
    # equal to the state from the request.
    browser_id = app.storage.browser["id"]
    auth_flow = AUTH_FLOW_STATES.get(browser_id, None)

    # No auth flow is known for this browser yet. Send the user back to the login page.
    if auth_flow is None:
        return ui.navigate.to("/login")

    # Extract the state that was reported from the redirector - which should be Microsoft and thus correct,
    # but we should verify this
    params_auth_state = client.request.query_params["state"]

    # If the states are not equal, we will not continue
    if params_auth_state != auth_flow["state"]:
        ui.label(f"Invalid state parameter")
        return

    # Acquire token by auth code flow
    query_params = dict(client.request.query_params)
    result = msal_app.acquire_token_by_auth_code_flow(auth_flow, query_params)

    if "error" in result:
        ui.label(f"Error: {result['error']} - {result.get('error_description')}")
        return

    # Verify the claims made in the token by decoding the encrypted contents using the Microsoft Entra public key for
    # our tenant.
    id_token = result.get("id_token")
    claims = validate_token(id_token, TENANT_NAME)

    if not claims:
        ui.label("Error: Invalid ID token.")
        return

    # Store user information as received from Azure Entra
    USER_DATA[browser_id] = claims

    # Send the user back to home, from where they will be further redirected to the actual app
    ui.navigate.to("/")


@ui.page("/logout")
def logout():
    """
    This page deletes the user information from memory so no user is logged in as far as our application is concerned.
    The user is redirected to home. Nothing is displayed to the user.
    """

    # Delete anything related to the user's information
    browser_id = app.storage.browser["id"]

    if browser_id in AUTH_FLOW_STATES:
        del AUTH_FLOW_STATES[browser_id]

    if browser_id in USER_DATA:
        del USER_DATA[browser_id]

    if "user" in app.storage.user:
        del app.storage.user["user"]

    # Redirect to the Microsoft Entra logout endpoint to invalidate the session and then send the user back home
    return RedirectResponse(f"{ENTRA_LOGOUT_ENDPOINT}?post_logout_redirect_uri={BASE_APPLICATION_URL}")


@ui.page("/actual_app")
def start_actual_app():
    # Check whether the user has logged in and user information is available
    if "user" not in app.storage.user:
        return RedirectResponse("/")

    user = app.storage.user["user"]

    with ui.column().classes("w-full items-center"):
        # Display log in components
        ui.markdown(f"## NiceGUI Entra authentication app\n You have logged in!\nWelcome {user['name']}").style(
            "white-space: pre-wrap"
        )

        ui.button("Logout", on_click=lambda: ui.navigate.to("/logout"))


ui.run(
    host="0.0.0.0",
    port=8080,
    storage_secret=str(uuid.uuid4()),
)
