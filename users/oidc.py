"""
OpenID Connect login (authorization code flow with PKCE).

Bugsink only uses OIDC to answer the question "which existing Bugsink account is this?": the email address is read
from the provider's userinfo endpoint and matched against an existing (active) user. No accounts are created, no
groups/roles are synced.

Note that we never parse or verify the id_token: the email comes from a direct (TLS-secured, access-token
authenticated) call to the provider's userinfo endpoint. This keeps us free of JWT/crypto dependencies while the
answer is just as trustworthy: it comes straight from the provider rather than through the browser.
"""

import base64
import hashlib
import secrets
from urllib.parse import urlencode

import requests
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils.translation import gettext as _

from bugsink.app_settings import get_settings


WELL_KNOWN_PATH = "/.well-known/openid-configuration"

TIMEOUT = 10

# The discovery document is cached for the lifetime of the process: endpoints don't move, and if they do, a restart is
# an acceptable price to pay for not having to think about cache invalidation.
_discovery_cache = {}


User = get_user_model()


class OIDCError(Exception):
    """Anything that makes an OIDC login fail; the message is shown to the user on the login page."""


def is_enabled():
    return bool(get_settings().OIDC_DISCOVERY_URL)


def discovery_url():
    url = get_settings().OIDC_DISCOVERY_URL
    return url if WELL_KNOWN_PATH in url else url.rstrip("/") + WELL_KNOWN_PATH


def _json_request(method, url, what, **kwargs):
    try:
        response = requests.request(method, url, timeout=TIMEOUT, **kwargs)
    except requests.RequestException:
        raise OIDCError(_("Could not reach the identity provider for the %s.") % what) from None

    if response.status_code != 200:
        raise OIDCError(_("The identity provider returned HTTP %(status)s for the %(what)s.") % {
            "status": response.status_code, "what": what})

    try:
        return response.json()
    except ValueError:
        raise OIDCError(_("The identity provider returned a non-JSON response for the %s.") % what) from None


def get_provider_config():
    url = discovery_url()
    if url not in _discovery_cache:
        _discovery_cache[url] = _json_request("GET", url, _("discovery document"))
    return _discovery_cache[url]


def _endpoint(name):
    config = get_provider_config()
    if not config.get(name):
        raise OIDCError(_("The identity provider's discovery document has no %s.") % name)
    return config[name]


def make_pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=")
    return verifier, challenge.decode("ascii")


def authorization_url(redirect_uri, state, code_challenge):
    endpoint = _endpoint("authorization_endpoint")

    params = urlencode({
        "response_type": "code",
        "client_id": get_settings().OIDC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": get_settings().OIDC_SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })

    return endpoint + ("&" if "?" in endpoint else "?") + params


def exchange_code(code, redirect_uri, code_verifier):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    # client_secret_basic is the spec's default; we only send the secret in the body when the provider says so.
    auth_methods = get_provider_config().get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
    if "client_secret_basic" in auth_methods:
        kwargs = {"auth": (get_settings().OIDC_CLIENT_ID, get_settings().OIDC_CLIENT_SECRET)}
    else:
        data["client_id"] = get_settings().OIDC_CLIENT_ID
        data["client_secret"] = get_settings().OIDC_CLIENT_SECRET
        kwargs = {}

    token = _json_request("POST", _endpoint("token_endpoint"), _("token request"), data=data, **kwargs)

    if not token.get("access_token"):
        raise OIDCError(_("The identity provider did not return an access token."))

    return token["access_token"]


def get_email(access_token):
    claims = _json_request(
        "GET", _endpoint("userinfo_endpoint"), _("userinfo request"),
        headers={"Authorization": "Bearer " + access_token})

    if not claims.get("email"):
        raise OIDCError(_("The identity provider did not provide an email address."))

    if claims.get("email_verified") is False:
        raise OIDCError(_("The identity provider reports the email address %s as unverified.") % claims["email"])

    return claims["email"]


def find_user(email):
    # Bugsink uses the email address as the username, but accounts created with `createsuperuser` (or in the admin) may
    # have something else there, so we look at both fields. Matching is case-insensitive: providers are not consistent
    # about the casing of the email they hand out.
    matches = list(User.objects.filter(Q(username__iexact=email) | Q(email__iexact=email)))

    if len(matches) > 1:
        raise OIDCError(_("More than one Bugsink account matches the email address %s.") % email)

    if len(matches) == 0 or not matches[0].is_active:
        raise OIDCError(_("No active Bugsink account exists for the email address %s.") % email)

    return matches[0]
