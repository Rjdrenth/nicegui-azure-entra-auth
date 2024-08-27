import os
import uuid
from urllib.parse import parse_qs, urlparse

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

jwks_url = f"https://login.microsoftonline.com/{TENANT_NAME}/discovery/v2.0/keys"
response = requests.get(jwks_url)
jwks = response.json()
TENANT_PUBLIC_KEY = RSAAlgorithm.from_jwk(jwks["keys"][0])

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

    # Obtain auth_state from referrer if present. If so, use it to determine whether a user is logged in
    auth_state = None
    user = None

    # Obtain the `state` parameter from the `referer` URL. If this information is not present, e.g. if this is a fresh
    # session and no one is logged in yet, or if it comes from a place other than Entra, then this will fail.
    try:
        url = client.request.headers.get("referer")
        if url:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            auth_state = query_params.get("state", [None])[0]

            # If an auth state was found, we can use it to obtain the user information
            if auth_state and auth_state in USER_DATA:
                user = USER_DATA[auth_state]
                app.storage.user["auth_state"] = auth_state
                app.storage.user["user"] = user
    except Exception as e:
        print(f"Error processing the state: {e}")

    # if "user" was not initialised
    if not user:
        with ui.column().classes("w-full items-center"):
            # Display log in components
            ui.markdown(f"## NiceGUI Entra authentication app\n Welcome to this app. Please log in").style(
                "white-space: pre-wrap"
            )

            ui.button("Login with Microsoft", on_click=lambda: ui.navigate.to("/login"))
    else:
        # If the user is logged in, redirect them to the actual app
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
    AUTH_FLOW_STATES[auth_flow["state"]] = auth_flow

    # And redirect the user to the Entra login page
    return RedirectResponse(auth_flow["auth_uri"])


def validate_token(id_token):
    """Validate the JWT token using the public key from Azure AD."""
    try:
        # Decode the token, verifying the signature and claims
        decoded_token = jwt.decode(id_token, TENANT_PUBLIC_KEY, algorithms=["RS256"], audience=CLIENT_ID)
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

    # Collect the relevant information to obtain a token from Azure
    auth_state = client.request.query_params["state"]

    # Validate the state parameter to protect against CSRF
    if auth_state not in AUTH_FLOW_STATES:
        ui.label("Error: Invalid state parameter.")
        return

    auth_flow = AUTH_FLOW_STATES[auth_state]

    query_params = dict(client.request.query_params)

    # Acquire token by auth code flow
    result = msal_app.acquire_token_by_auth_code_flow(auth_flow, query_params)

    if "error" in result:
        ui.label(f"Error: {result['error']} - {result.get('error_description')}")
        return

    # Validate and store the ID token
    id_token = result.get("id_token")
    claims = validate_token(id_token)

    if not claims:
        ui.label("Error: Invalid ID token.")
        return

    # Store user information as received from Azure Entra
    USER_DATA[auth_state] = claims

    # Send the user back to home, from where they will be further redirected to the actual app
    ui.navigate.to("/")


@ui.page("/logout")
def logout():
    """
    This page deletes the user information from memory so no user is logged in as far as our application is concerned.
    The user is redirected to home. Nothing is displayed to the user.
    """

    # Delete anything related to the user's information
    auth_state = app.storage.user.get("auth_state", None)

    if auth_state in AUTH_FLOW_STATES:
        del AUTH_FLOW_STATES[auth_state]

    if auth_state in USER_DATA:
        del USER_DATA[auth_state]

    if "auth_state" in app.storage.user:
        del app.storage.user["auth_state"]

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
