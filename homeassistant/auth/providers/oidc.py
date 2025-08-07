"""OpenID Connect auth provider."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Mapping
import hashlib
from http import HTTPStatus
from ipaddress import ip_address
import json
import logging
import secrets
import time
from typing import Any, cast
import urllib.parse

import aiohttp
from aiohttp import web
import jwt
import jwt.algorithms
import voluptuous as vol

from homeassistant import data_entry_flow
from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_READ_ONLY, GROUP_ID_USER
from homeassistant.components.auth import create_auth_code
from homeassistant.components.http.auth import async_user_not_allowed_do_auth
from homeassistant.components.http.ban import log_invalid_auth, process_success_login
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.network import NoURLAvailableError, get_url

from ..models import AuthFlowContext, AuthFlowResult, Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

CONF_DISCOVERY_URL = "discovery_url"
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_REQEUST_TIMEOUT = "request_timeout"
CONF_SCOPES = "scopes"

# A claim or list of claims to check to determine the username.
# These claims are checked in order, and the first one found is used.
# Default: [email, name, preferred_username]
CONF_CLAIM_USERNAME = "username_claim"

# Behavior of group assignment:
# - If admin_role is None or empty, all users that log in with OIDC will be
#   granted administrator privileges.
#   Otherwise, users with this role will be granted administrator privileges.
# - If user_role is None or empty, all users will not granted administrator
#   privileges due to admin_role will be given normal user privileges.
#   Otherwise, users with this role will be granted user privileges.
# - If readonly_role is None or empty, all users will not granted administrator
#   or user privileges will be given read-only privileges.
#   Otherwise, users with this role will be granted readonly privileges.
#   Users without this role set will be denied login access.
#
# A claim or list of claims to check to determine the roles.
# Default: "groups"
CONF_CLAIM_ROLES = "roles_claim"
CONF_ROLE_ADMIN = "admin_role"
CONF_ROLE_USER = "user_role"
CONF_ROLE_READ_ONLY = "readonly_role"

# If required_signing_algorithm is set, we reject token replies
# that use a different signing algorithm. This can be used if you have
# registered the client_id on the provider to use a specific signing
# algorithm.
CONF_REQUIRED_SIGNING_ALGORITHM = "required_signing_algorithm"
# If max_token_age is set, we will reject ID tokens that are older
# than this age by the time we receive them. This value is in seconds.
CONF_MAX_TOKEN_AGE = "max_token_age"


# Many OpenID Providers send JWT Access Tokens (RFC 9068).
# In theory clients are supposed to treat access tokens just as opaque data,
# and shouldn't try to parse them. However, some implementations like
# Keycloak appear to expect users to parse access tokens in some cases,
# and can be configured to return claims in the access token which
# aren't present in the ID token or userinfo. Other clients like
# grafana do parse data from the access token.
#
# If try_parse_jwt_access_token is True we will also try to look for
# claims in the access token to find username & group info.
CONF_PARSE_JWT_ACCESS_TOKEN = "parse_jwt_access_token"

PROVIDER_NAME = "oidc"
AUTH_CALLBACK_PATH = f"/auth/{PROVIDER_NAME}/callback"
AUTH_CALLBACK_NAME = f"auth:{PROVIDER_NAME}:callback"
AUTH_CALLBACK_STEP = "auth_response_callback"

CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_DISCOVERY_URL): cv.url,
        vol.Required(CONF_CLIENT_ID): str,
        vol.Optional(CONF_CLIENT_SECRET): str,
        vol.Optional(CONF_SCOPES): vol.Any(str, [str]),
        vol.Optional(CONF_REQUIRED_SIGNING_ALGORITHM): str,
        vol.Optional(CONF_MAX_TOKEN_AGE, default=3600): int,
        vol.Optional(CONF_REQEUST_TIMEOUT, default=30.0): float,
        vol.Optional(
            CONF_CLAIM_USERNAME, default=["email", "name", "preferred_username"]
        ): vol.Any(str, [str]),
        vol.Optional(CONF_CLAIM_ROLES, default="groups"): vol.Any(str, [str]),
        vol.Optional(CONF_ROLE_ADMIN, default="admin"): str,
        vol.Optional(CONF_ROLE_USER): str,
        vol.Optional(CONF_ROLE_READ_ONLY): str,
        vol.Optional(CONF_PARSE_JWT_ACCESS_TOKEN, default=False): bool,
    },
    extra=vol.PREVENT_EXTRA,
)

DISCOVERY_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("issuer"): vol.Url(),
        vol.Required("authorization_endpoint"): vol.Url(),
        vol.Required("token_endpoint"): vol.Url(),
        vol.Optional("userinfo_endpoint"): vol.Url(),
        vol.Required("jwks_uri"): vol.Url(),
        vol.Required("id_token_signing_alg_values_supported"): [str],
    },
    extra=vol.ALLOW_EXTRA,
)
JWT_HEADER_SCHEMA = vol.Schema(
    {
        vol.Required("alg"): str,
        vol.Optional("kid"): str,
    },
    extra=vol.ALLOW_EXTRA,
)
ID_TOKEN_PAYLOAD_SCHEMA = vol.Schema(
    {
        vol.Required("iss"): str,
        vol.Required("sub"): str,
        vol.Required("aud"): str,
        vol.Optional("azp"): str,
        vol.Required("exp"): int,
        vol.Required("iat"): int,
        vol.Optional("nonce"): str,
        vol.Optional("at_hash"): str,
    },
    extra=vol.ALLOW_EXTRA,
)

_LOGGER = logging.getLogger(__name__)


class OidcError(HomeAssistantError):
    """Raised when an error occurs during OIDC authentication."""


@AUTH_PROVIDERS.register(PROVIDER_NAME)
class OidcAuthProvider(AuthProvider):
    """OpenID Connect auth provider.

    Authenticates the user using an external OpenID Provider.
    See https://openid.net/specs/openid-connect-core-1_0.html
    """

    DEFAULT_TITLE = "OpenID Connect"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an Home Assistant auth provider."""
        super().__init__(*args, **kwargs)

        self.client_id = self.config[CONF_CLIENT_ID]
        self.client_secret: str | None = self.config.get(CONF_CLIENT_SECRET, None)
        self.discovery_url = self.config[CONF_DISCOVERY_URL]
        self.request_timeout = aiohttp.ClientTimeout(
            total=self.config[CONF_REQEUST_TIMEOUT]
        )
        self.required_signing_alg = self.config.get(CONF_REQUIRED_SIGNING_ALGORITHM)
        self.max_issue_age = self.config.get(CONF_MAX_TOKEN_AGE)
        self.try_parse_jwt_access_token = self.config.get(CONF_PARSE_JWT_ACCESS_TOKEN)

        def _ensure_list(value: str | list[str]) -> list[str]:
            if not isinstance(value, list):
                return [value]
            return value

        self.username_claims = _ensure_list(self.config[CONF_CLAIM_USERNAME])
        self.roles_claims = _ensure_list(self.config[CONF_CLAIM_ROLES])
        self.admin_role = self.config.get(CONF_ROLE_ADMIN)
        self.user_role = self.config.get(CONF_ROLE_USER)
        self.readonly_role = self.config.get(CONF_ROLE_READ_ONLY)

        scopes_config = self.config.get(CONF_SCOPES)
        if scopes_config is None:
            scopes_list = []
        elif isinstance(scopes_config, str):
            scopes_list = scopes_config.split()
        else:
            scopes_list = scopes_config
        required_scopes = ("profile", "openid")
        for scope in required_scopes:
            if scope not in scopes_list:
                scopes_list.insert(0, scope)
        self.scope = " ".join(scopes_list)

        # Note: authorization providers are initialized before the http component,
        # so we unfortunately cannot register OidcCallbackView yet.
        self.callback_view: None | OidcCallbackView = None

    @property
    def support_mfa(self) -> bool:
        """The OIDC auth provider does not support MFA.

        When using OpenID Connect, the OpenID Provider itself should typically
        be responsible for MFA, rather than doing additional MFA locally after
        the OpenID Provider has successfully authenticated the client.
        """
        # Doing MFA on the client (Home Assistant) doesn't really make sense
        # for OIDC.
        #
        # Additionally, from a technical perspective we don't support
        # additional local MFA after OpenID authentication because doing so
        # would require redirecting the user back to the /auth/authorize
        # endpoint in order to complete MFA. The /auth/authorize endpoint would
        # need to be updated to know how to resume an in-progress login flow
        # instead of always starting a new flow, and it currently can't do
        # this.
        return False

    async def async_get_discovery_data(self) -> Any:
        """Get the OpenID Provider Metadata.

        This fetches provider metadata from the discovery URL.
        See https://openid.net/specs/openid-connect-discovery-1_0.html
        """
        # Note: it would perhaps be nice to cache the discovery data if allowed by the server.
        #
        # I haven't tested with very many implementations yet, but Keycloak always specifies "no-store"
        # in the Cache-Control response header, so I for now I haven't implemented any caching.
        try:
            response = await async_get_clientsession(self.hass, verify_ssl=True).get(
                self.discovery_url,
                timeout=self.request_timeout,
            )
        except (aiohttp.ClientError, TimeoutError) as err:
            msg = f"Error communicating with OpenID provider: {err}"
            _LOGGER.error(msg)
            raise OidcError(msg) from err

        if not response.ok:
            msg = (
                f"Error response when getting OpenID discovery data: {response.status}"
            )
            _LOGGER.error(msg)
            raise OidcError(msg)

        discovery_data = await response.json()
        _debug_log_json("OICD discovery data", discovery_data)
        return discovery_data

    async def async_get_jwks(self, jwks_uri: str) -> Any:
        """Get JSON Web Key Set from the specified URI.

        This retrieves the keys used by the provider for asymmetric signing.
        The URL supplied should generally be the jwks_uri from the OpenID
        Provider Metadata.
        """
        # Note: it would perhaps be nice to perform caching of the response
        # based on the response Cache-Control headers.
        try:
            response = await async_get_clientsession(self.hass, verify_ssl=True).get(
                jwks_uri,
                timeout=self.request_timeout,
            )
        except (aiohttp.ClientError, TimeoutError) as err:
            msg = f"Error fetching JWKS from OpenID provider: {err}"
            _LOGGER.error(msg)
            raise OidcError(msg) from err

        if not response.ok:
            msg = f"Failed to fetch JWKS data from OpenID provider: error {response.status}"
            _LOGGER.error(msg)
            raise OidcError(msg)

        jwks = await response.json()
        _debug_log_json("JWKS data", jwks)
        return jwks

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> Oauth2LoginFlow:
        """Return the data flow for logging in with auth provider."""
        if self.callback_view is None:
            self.callback_view = OidcCallbackView(self.hass)
            self.hass.http.register_view(self.callback_view)

        return Oauth2LoginFlow(self)

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        credential_data: dict[str, str] = dict(**flow_result)
        sub = flow_result["sub"]
        for credentials in await self.async_credentials():
            if credentials.data["sub"] == sub:
                await self._async_ensure_credential_up_to_date(
                    credentials, credential_data
                )
                return credentials

        # Create new credentials.
        return self.async_create_credentials(credential_data)

    async def _async_ensure_credential_up_to_date(
        self, credentials: Credentials, credential_data: dict[str, str]
    ) -> None:
        if credential_data == credentials.data:
            return

        self.hass.auth.async_update_user_credentials_data(credentials, credential_data)
        credentials.data = credential_data

        # At the moment we don't ever link OIDC credentials to non-OIDC users.
        # Automatically update the existing user's name and group based on the current OIDC data.
        user = await self.hass.auth.async_get_user_by_credentials(credentials)
        if user is None:
            # We normally expect to find an existing user, but maybe something
            # failed earlier between saving credentials and creating the user.
            return

        await self.hass.auth.async_update_user(
            user,
            name=credential_data["display_name"],
            group_ids=[credential_data["group"]],
        )

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials."""
        return UserMeta(
            name=credentials.data["display_name"],
            is_active=True,
            group=credentials.data.get("group"),
            local_only=False,
        )


def jwt_b64encode(value: str) -> str:
    """Perform URL-safe base64 encoding with no padding.

    This encoding is used by various JWT RFCs.
    For instance, see RFC 7515 Appendix C
    """
    return jwt_b64encode_bytes(value.encode("utf-8"))


def jwt_b64encode_bytes(value: bytes) -> str:
    """Perform URL-safe base64 encoding with no padding.

    This version accepts bytes.
    """
    out_bytes = base64.urlsafe_b64encode(value).rstrip(b"=")
    return out_bytes.decode("ascii")


def jwt_b64decode_bytes(value: str) -> bytes:
    """Perform URL-safe base64 decoding with no padding.

    This encoding is used by various JWT RFCs.
    For instance, see RFC 7515 Appendix C
    """
    value_bytes = value.encode("ascii")
    mod_len = len(value_bytes) % 4
    if mod_len == 0:
        pass
    elif mod_len == 2:
        value_bytes = value_bytes + b"=="
    elif mod_len == 3:
        value_bytes = value_bytes + b"="
    else:
        raise ValueError("malformed base64 input")

    return base64.urlsafe_b64decode(value_bytes)


def jwt_b64decode(value: str) -> str:
    """Perform URL-safe base64 decoding with no padding.

    This version assumes the decoded data is a UTF-8 encoded string, and
    returns it as a string.
    """
    out_bytes = jwt_b64decode_bytes(value)
    return out_bytes.decode("utf-8")


class Oauth2LoginFlow(LoginFlow[OidcAuthProvider]):
    """Handler for OIDC login flows."""

    def __init__(self, auth_provider: OidcAuthProvider) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)

        # State generated for the authentication request
        self.state_token: str | None = None
        self.nonce: str | None = None
        self.callback_url: str | None = None
        self.code_verifier: str | None = None

        # Authentication response state
        self.id_token: dict[str, Any] | None = None
        self.access_token: str | None = None
        self.credential_data: dict[str, str] | None = None

        # Discovered provider metadata
        self.token_endpoint: str | None = None
        self.userinfo_endpoint: str | None = None
        self.jwt_signing_algos: list[str] | None = None
        self.issuer: str | None = None
        self.jwks_task: asyncio.Task[Any] | None = None
        self.jwks_keys: list[Any] | None = None

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the initial step of the login flow.

        This step simply displays the OpenID Provider Name, and gives the user
        a chance to decide whether to proceed or select a different
        AuthProvider.
        """
        return self._auth_request_step()

    def _auth_request_step(self, error: str | None = None) -> AuthFlowResult:
        errors: dict[str, str] = {}
        if error is not None:
            errors["base"] = error
        return self.async_show_form(
            step_id="auth_request",
            data_schema=vol.Schema(
                {
                    vol.Required("provider"): self._auth_provider.name,
                    vol.Required("store_token"): bool,
                }
            ),
            description_placeholders={},
            errors=errors,
        )

    async def async_step_auth_request(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Trigger the authentication request to the OpenID Provider.

        This validates the user input, fetches the necessary provider metadata,
        and generates the Authentication Request URL where the client should be
        redirected.

        We always use the Authorization Code Flow.
        See section 3.1 of https://openid.net/specs/openid-connect-core-1_0.html
        """
        _LOGGER.debug("OIDC: start auth_request step: user_input=%r", user_input)
        if user_input is None:
            return self._auth_request_step()

        try:
            hass_url = get_url(self._auth_provider.hass)
        except NoURLAvailableError:
            _LOGGER.error("Unable to determine return callback URL")
            return self._auth_request_step(error="no_callback_url")
        self.callback_url = f"{hass_url}{AUTH_CALLBACK_PATH}"

        raw_discovery_data = await self._auth_provider.async_get_discovery_data()
        try:
            discovery_data = DISCOVERY_DATA_SCHEMA(raw_discovery_data)
        except vol.Invalid as err:
            _LOGGER.error("Invalid OIDC discovery data: %s", err)
            return self._auth_request_step(error="provider_error")

        auth_endpoint = discovery_data["authorization_endpoint"]
        self.token_endpoint = discovery_data["token_endpoint"]
        self.userinfo_endpoint = discovery_data.get("userinfo_endpoint")
        jwks_uri = discovery_data["jwks_uri"]
        self.jwt_signing_algos = discovery_data.get(
            "id_token_signing_alg_values_supported"
        )
        self.issuer = discovery_data["issuer"]

        url_keys = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
        ]
        for key in url_keys:
            url = discovery_data.get(key)
            if url is None:
                continue
            if urllib.parse.urlparse(url).scheme != "https":
                _LOGGER.error("OIDC metadata: %s is not an HTTPS url: %s", key, url)
                return self._auth_request_step(error="provider_error")

        # Start fetching the JWKS in a background task.
        # We don't need this data until after we get the token.
        self.jwks_task = asyncio.create_task(
            self._auth_provider.async_get_jwks(jwks_uri)
        )

        # We store our flow ID and a random token in the state parameter.
        # The token is verified in the callback, to mitigate CSRF attacks.
        self.state_token = secrets.token_urlsafe(12)
        store_token = user_input.get("store_token", False)
        state_list = [self.flow_id, self.state_token, store_token]
        state = jwt_b64encode(json.dumps(state_list))

        self.nonce = secrets.token_urlsafe()

        # PKCE (RFC 7636)
        # The code_verifier length should be between 43 and 128 characters.
        # Since token_urlsafe() base64 encodes the result, this means a
        # requested length of 32 to 96 bytes.
        self.code_verifier = secrets.token_urlsafe(48)
        code_challenge = jwt_b64encode_bytes(
            hashlib.sha256(self.code_verifier.encode("ascii")).digest()
        )
        code_challenge_method = "S256"

        params = {
            "response_type": "code",
            "client_id": self._auth_provider.client_id,
            "redirect_uri": self.callback_url,
            "scope": self._auth_provider.scope,
            "state": state,
            "nonce": self.nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        url_params = urllib.parse.urlencode(params)
        auth_url = f"{auth_endpoint}?{url_params}"
        _LOGGER.debug("OIDC auth via %s", auth_url)
        return self.async_external_step(
            step_id=AUTH_CALLBACK_STEP,
            url=auth_url,
        )

    async def async_step_auth_response_callback(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Process the Authorization Response callback.

        This performs validation of the response and computes user credentials
        if login was successful.
        """
        _LOGGER.debug(
            "OIDC: start auth_response_callback step: user_input=%r", user_input
        )

        # Verify the state token
        if not user_input:
            raise OidcError("invalid state")
        if user_input.get("state_token", None) != self.state_token:
            raise OidcError("invalid state")

        # Send a request to the authentication server to get an auth token
        response = await self._async_get_auth_token(user_input["code"])
        self.id_token, self.access_token = await self._async_validate_token_response(
            response
        )

        # Prepare the credential data.
        self.credential_data = await self._async_prepare_credentials(
            self.id_token, self.access_token
        )
        _LOGGER.debug("credential_data=%r", self.credential_data)

        # The data_entry_flow code checks to ensure that we call
        # async_external_step_done() to finish an external step. "finalize" is
        # only broken out into a separate step because of this requirement,
        # which prevents us from directly calling async_finish() here.
        return self.async_external_step_done(next_step_id="finalize")

    async def async_step_finalize(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Complete the login flow and return credentials."""
        _LOGGER.debug("OIDC: start finalize step: user_input=%r", user_input)
        assert self.credential_data is not None
        return await self.async_finish(self.credential_data)

    async def _async_get_auth_token(self, code: str) -> Any:
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.callback_url,
            "client_id": self._auth_provider.client_id,
        }
        if self._auth_provider.client_secret:
            params["client_secret"] = self._auth_provider.client_secret
        if self.code_verifier:
            params["code_verifier"] = self.code_verifier

        assert self.token_endpoint is not None
        try:
            response = await async_get_clientsession(self.hass, verify_ssl=True).post(
                self.token_endpoint,
                data=params,
                timeout=self._auth_provider.request_timeout,
            )
        except (aiohttp.ClientError, TimeoutError) as err:
            msg = f"Error getting auth token from OpenID provider: {err}"
            _LOGGER.error(msg)
            raise OidcError(msg) from err

        response_data = await response.json()
        if not response.ok:
            server_error = response_data.get("error")
            error_msg = f"received error {response.status} from authorization server: {server_error}"
            raise OidcError(error_msg)

        return response_data

    async def _async_validate_token_response(
        self, response: Any
    ) -> tuple[dict[str, Any], str]:
        # Validate the token response
        if not isinstance(response, dict):
            raise OidcError("bad token response received from authorization server")

        token_type = response.get("token_type", None)
        if isinstance(token_type, str):
            token_type = token_type.lower()
        if token_type != "bearer":
            raise OidcError(f"received unexpected token type: {token_type}")

        access_token = response.get("access_token", None)
        if access_token is None:
            raise OidcError("token reply is missing access_token")
        encoded_id_token = response.get("id_token", None)
        if encoded_id_token is None:
            raise OidcError("token reply is missing id_token")

        id_token = await self._async_process_id_token(encoded_id_token, access_token)
        return id_token, access_token

    async def _async_decode_jwt(
        self, token: str, token_type: str, required_alg: str | None = None
    ) -> tuple[jwt.algorithms.Algorithm, dict[str, Any]]:
        # OIDC always uses JWS Compact Serialization. See RFC 7515
        encoded_header = token.split(".", 1)[0]
        header_json = json.loads(jwt_b64decode(encoded_header))
        try:
            header = JWT_HEADER_SCHEMA(header_json)
        except vol.Invalid as err:
            raise OidcError(f"invalid JWT header in {token_type}: {err}") from err
        key_id = header["kid"]
        alg_name = header["alg"]
        if required_alg is not None and alg_name != required_alg:
            raise OidcError(
                f"received ID token with bad signing algorithm: {alg_name!r}"
            )
        alg = jwt.get_algorithm_by_name(alg_name)

        key = await self._async_get_signing_key(alg_name, key_id)
        payload = jwt.decode(
            token,
            key=key,
            algorithms=self.jwt_signing_algos,
            options={"verify_aud": False},
        )
        _debug_log_json(token_type, payload)
        return alg, payload

    async def _async_process_id_token(
        self, id_token: str, access_token: str
    ) -> dict[str, Any]:
        alg, raw_payload = await self._async_decode_jwt(
            id_token, "ID Token", required_alg=self._auth_provider.required_signing_alg
        )
        try:
            payload: dict[str, Any] = ID_TOKEN_PAYLOAD_SCHEMA(raw_payload)
        except vol.Invalid as err:
            raise OidcError(f"received invalid ID token: {err}") from err

        # ID Token Validation:
        # Section 3.1.3.7 of https://openid.net/specs/openid-connect-core-1_0.html
        # 2. The Issuer Identifier for the OpenID Provider (which is typically
        #    obtained during Discovery) MUST exactly match the value of the
        #    iss (issuer) Claim
        iss = payload["iss"]
        if iss != self.issuer:
            raise OidcError(f"received ID token with bad issuer: {iss!r}")

        # 3. The Client MUST validate that the aud (audience) Claim contains
        # its client_id value registered at the Issuer identified by the iss
        # (issuer) Claim as an audience. The aud (audience) Claim MAY contain
        # an array with more than one element. The ID Token MUST be rejected if
        # the ID Token does not list the Client as a valid audience, or if it
        # contains additional audiences not trusted by the Client.
        aud = payload["aud"]
        if aud != self._auth_provider.client_id:
            raise OidcError(f"received ID token with bad audience: {aud!r}")

        # 4. not relevant to us; not using azp
        # 5. This validation MAY include that when an azp (authorized party)
        # Claim is present, the Client SHOULD verify that its client_id is the
        # Claim Value
        azp = payload.get("azp")
        if azp is not None and azp != self._auth_provider.client_id:
            raise OidcError(f"received ID token with bad authorized party: {azp!r}")

        # 6. We can use TLS server validation instead of checking the ID token
        #    signature.
        # In our case we always check both.

        # 7. The alg value SHOULD be the default of RS256 or the algorithm sent
        # by the Client in the id_token_signed_response_alg parameter during
        # Registration.
        # We check this in _async_decode_jwt()

        # 8. MAC-based algorithms use the client_secret as the key.
        # We handle this in _async_get_signing_key()

        # 9. The current time MUST be before the time represented by the exp Claim.
        exp = payload["exp"]
        now = time.time()
        if exp < now:
            exp_str = time.ctime(exp)
            raise OidcError(f"received expired ID token: {exp_str}")

        # 10: The iat Claim can be used to reject tokens that were issued too far
        # away from the current time.
        age = now - payload["iat"]
        if age > self._auth_provider.max_issue_age:
            iat_str = time.ctime(exp)
            raise OidcError(f"received stale ID token: issued at {iat_str}")

        # 11. If a nonce value was sent in the Authentication Request, a nonce
        # Claim MUST be present and its value checked to verify that it is the
        # same value as the one that was sent in the Authentication Request.
        # The Client SHOULD check the nonce value for replay attacks. The
        # precise method for detecting replay attacks is Client specific.
        nonce = payload.get("nonce")
        if nonce is None:
            raise OidcError("ID token is missing nonce")
        if nonce != self.nonce:
            raise OidcError("incorrect nonce in ID token")

        # 12 and 13 are not relevant to us.

        # Section 3.1.3.8: at_hash validation
        # The at_hash field contains the left-most half of the access token hash.
        at_hash_field = payload.get("at_hash")
        if at_hash_field is not None:
            expected_at_hash = jwt_b64decode_bytes(at_hash_field)
            at_hash = alg.compute_hash_digest(access_token.encode("utf-8"))
            at_hash_left = at_hash[: len(at_hash) // 2]
            if at_hash_left != expected_at_hash:
                raise OidcError("bad access token hash")

        return payload

    async def _async_get_signing_key(
        self, alg_name: str, key_id: str | None
    ) -> bytes | jwt.PyJWK:
        if alg_name.startswith("HS"):
            # Symmetric HMAC algorithms use the UTF-8 encoded client_secret as
            # the key.
            if not self._auth_provider.client_secret:
                raise OidcError("cannot validate MAC signature without a client_secret")
            return self._auth_provider.client_secret.encode("utf-8")

        # Asymmetric algorithms use sign using the provider key in the JWKS.

        if self.jwks_keys is None:
            assert self.jwks_task is not None
            jwks = await self.jwks_task
            self.jwks_task = None
            if not isinstance(jwks, dict):
                raise OidcError("bad JWKS data")
            jwks_keys = jwks.get("keys")
            if not isinstance(jwks_keys, list):
                raise OidcError("bad JWKS keys data")
            self.jwks_keys = jwks_keys

        if not key_id:
            # The kid can be omitted if there is just 1 key
            if len(self.jwks_keys) == 1:
                key_info = self.jwks_keys[0]
                return jwt.PyJWK(key_info)
            raise OidcError("no key ID specified for ID token signature")

        for key_info in self.jwks_keys:
            if not isinstance(key_info, dict):
                # Ignore bad data
                continue
            if key_info.get("kid") == key_id:
                return jwt.PyJWK(key_info)

        raise OidcError(f"no JWKS key found with ID {key_id!r}")

    async def _async_prepare_credentials(
        self, id_token: dict[str, Any], access_token: str
    ) -> dict[str, Any]:
        # Create user credential data based on claims.
        #
        # Depending on the provider configuration, it may return claims either
        # in the ID token, via the access token, or via the userinfo endpoint.
        # We search through these locations in turn until we have found
        # everything we need.

        sub = id_token["sub"]
        credential_data: dict[str, str] = {"sub": sub}

        # First try getting info from the ID token.
        # If we got everything needed we can return early.
        if self._update_credential_data(credential_data, id_token):
            return credential_data

        if self._auth_provider.try_parse_jwt_access_token:
            try:
                _, access_token_payload = await self._async_decode_jwt(
                    access_token, "Access Token"
                )
            except (ValueError, jwt.InvalidTokenError):
                # The token may not be JWT data
                access_token_payload = None

            if access_token_payload is not None:
                if self._update_credential_data(credential_data, access_token_payload):
                    return credential_data

        userinfo = await self._async_fetch_userinfo(id_token, access_token)
        if self._update_credential_data(credential_data, userinfo):
            return credential_data

        if "display_name" not in credential_data:
            credential_data["display_name"] = sub
        if "group" not in credential_data:
            credential_data["group"] = self._group_from_roles([])
        return credential_data

    def _update_credential_data(
        self, credential_data: dict[str, str], token: dict[str, Any]
    ) -> bool:
        if "display_name" not in credential_data:
            for claim in self._auth_provider.username_claims:
                value = self._get_claim(token, claim)
                if value:
                    credential_data["display_name"] = value
                    break

        if "group" not in credential_data:
            for claim in self._auth_provider.roles_claims:
                value = self._get_claim(token, claim)
                if value is not None:
                    credential_data["group"] = self._group_from_roles(value)
                    break

        # Return true if all credential fields have been populated
        return "display_name" in credential_data and "group" in credential_data

    def _group_from_roles(self, roles: Any) -> str:
        if not isinstance(roles, list):
            roles = []

        role_priorities = [
            (self._auth_provider.admin_role, GROUP_ID_ADMIN),
            (self._auth_provider.user_role, GROUP_ID_USER),
            (self._auth_provider.readonly_role, GROUP_ID_READ_ONLY),
        ]
        for role, group in role_priorities:
            if role is None:
                return group
            if role in roles:
                return group

        raise OidcError("user roles do not grant access to Home Assistant")

    def _get_claim(self, token: Any, path: str) -> Any:
        """Extract a claim from a JSON token via a full path."""
        path_parts = path.split(".")
        cur_token: Any = token
        for part in path_parts:
            if isinstance(cur_token, dict):
                next_token = cur_token.get(part)
                if next_token is None:
                    return None
            elif isinstance(cur_token, list):
                try:
                    index = int(part)
                except ValueError:
                    return None
                if index < 0 or index >= len(cur_token):
                    return None
                next_token = cur_token[index]
            else:
                return None
            cur_token = next_token

        return cur_token

    async def _async_fetch_userinfo(
        self, id_token: dict[str, Any], access_token: str
    ) -> dict[str, Any]:
        userinfo_url = self.userinfo_endpoint
        if not userinfo_url:
            return {}

        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            response = await async_get_clientsession(self.hass, verify_ssl=True).get(
                userinfo_url,
                headers=headers,
                timeout=self._auth_provider.request_timeout,
            )
        except (aiohttp.ClientError, TimeoutError) as err:
            msg = f"Error getting userinfo from OpenID provider: {err}"
            _LOGGER.error(msg)
            raise OidcError(msg) from err

        if not response.ok:
            msg = f"Received error from OIDC userinfo endpoint: {response.status}"
            _LOGGER.error(msg)
            raise OidcError(msg)

        _LOGGER.debug("userinfo response: %s", response)
        content_type = response.headers.get("Content-Type")
        if content_type == "application/json":
            body = await response.json()
            _debug_log_json("userinfo", body)
            return cast(dict[str, Any], body)
        if content_type == "application/jwt":
            body = await response.read()
            _, payload = await self._async_decode_jwt(body.decode("utf-8"), "UserInfo")
            # Section 5.3.2 of https://openid.net/specs/openid-connect-core-1_0.html:
            # We must verify the returned sub value before using the result.
            if payload.get("sub") != id_token["sub"]:
                raise OidcError("invalid sub in userinfo")
            return payload
        raise OidcError(f"unknown userinfo Content-Type: {content_type!r}")


class OidcCallbackView(HomeAssistantView):
    """Callback used for the Authentication Response.

    The OpenID Provider will redirect the client to this endpoint after
    completing authentication.
    """

    url = AUTH_CALLBACK_PATH
    name = AUTH_CALLBACK_NAME
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the OICD authentication callback view."""
        self._flow_mgr = hass.auth.login_flow

    @log_invalid_auth
    async def get(self, request: web.Request) -> web.Response:
        """Handle resuming a login flow request after returning from an external step."""

        try:
            encoded_state = request.query["state"]
            state_json = jwt_b64decode(encoded_state)
            state_list = json.loads(state_json)
            flow_id, state_token, client_store_token = state_list
        except (KeyError, TypeError):
            return self.json_message("Invalid state", HTTPStatus.BAD_REQUEST)

        try:
            flow = self._flow_mgr.async_get(flow_id)
        except data_entry_flow.UnknownFlow:
            return self.json_message("Invalid flow ID", HTTPStatus.BAD_REQUEST)

        # do not allow change ip during login flow
        remote_address = ip_address(request.remote)  # type: ignore[arg-type]
        context = flow["context"]
        if context["ip_address"] != remote_address:
            return self._error_redirect("IP address changed", flow)

        if flow["step_id"] != AUTH_CALLBACK_STEP:
            return self._error_redirect("Invalid flow state", flow)

        try:
            try:
                result = await self._process_callback(request, flow_id, state_token)
            except Exception:
                self._flow_mgr.async_abort(flow_id)
                raise

            assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
            credentials = result["result"]
            code = await self._async_create_auth_code(credentials, request, context)
        except Exception as err:  # noqa: BLE001
            return self._error_redirect(str(err), flow)

        # Now use the downstream OAuth 2 data to redirect back to
        # the client that invoked us.
        params = {
            "code": code,
            "client_id": context["client_id"],
        }
        oauth_state = context.get("oauth_state")
        if oauth_state is not None:
            params["state"] = oauth_state
        if client_store_token:
            params["storeToken"] = "true"
        params_str = urllib.parse.urlencode(params)
        redirect_uri = context["redirect_uri"]
        if "?" in redirect_uri:
            location = f"{redirect_uri}&{params_str}"
        else:
            location = f"{redirect_uri}?{params_str}"
        raise web.HTTPFound(location)

    def _error_redirect(
        self,
        error: str,
        flow: AuthFlowResult,
    ) -> web.Response:
        try:
            hass_url = get_url(self._flow_mgr.hass)
        except NoURLAvailableError:
            return self.json_message(
                "unable to determine bas URL", HTTPStatus.INTERNAL_SERVER_ERROR
            )

        authorize_url = f"{hass_url}/auth/authorize"
        context = flow["context"]
        params = {
            "error": error,
            "client_id": context.get("client_id", ""),
            "redirect_uri": context.get("redirect_uri", ""),
            "state": context.get("oauth_state", ""),
        }
        params_str = urllib.parse.urlencode(params)
        headers = {"Location": f"{authorize_url}?{params_str}"}
        return web.Response(status=HTTPStatus.FOUND, headers=headers)

    async def _process_callback(
        self, request: web.Request, flow_id: str, state_token: str
    ) -> AuthFlowResult:
        error = request.query.get("error", None)
        if error is not None:
            error_desc = request.query.get("error_description", None)
            error_uri = request.query.get("error_uri", None)
            _LOGGER.debug(
                "OIDC auth failure: error=%r, error_desc=%r, error_uri=%r",
                error,
                error_desc,
                error_uri,
            )

            if not error_desc:
                error_desc = error
            error_msg = "authentication failed: {error_desc}"
            if error_uri:
                error_msg += f" ({error_uri})"
            raise OidcError(error_msg)

        code = request.query.get("code", None)
        if not code:
            raise OidcError("OIDC callback called without code")

        data = {
            "state_token": state_token,
            "code": code,
        }
        result = await self._flow_mgr.async_configure(flow_id, data)

        # We expect the result to always move on to the "finalize" step
        # on success. Go ahead and run this step now.
        assert result["type"] == data_entry_flow.FlowResultType.EXTERNAL_STEP_DONE
        return await self._flow_mgr.async_configure(flow_id, None)

    async def _async_create_auth_code(
        self, credentials: Credentials, request: web.Request, context: AuthFlowContext
    ) -> str:
        # The user can be None if this credential was never linked to a user before.
        hass = self._flow_mgr.hass
        user = await hass.auth.async_get_user_by_credentials(credentials)
        if user is not None and (
            user_access_error := async_user_not_allowed_do_auth(hass, user)
        ):
            raise OidcError(f"Login blocked: {user_access_error}")

        process_success_login(request)

        client_id = context.get("client_id", "")
        return create_auth_code(hass, client_id, credentials)


def _debug_log_json(message: str, value: Any) -> None:
    # This method is used to log JSON dictionaries that can be somewhat large.
    # Return early and skip doing any formatting work if logging is disabled.
    if not _LOGGER.isEnabledFor(logging.DEBUG):
        return

    # During development it can make the logs easier to read to logs
    # if we pretty-print the JSON data across multiple lines.
    pretty_print = False
    value_str = json.dumps(value, indent=2) if pretty_print else repr(value)
    _LOGGER.debug("%s: %s", message, value_str)
