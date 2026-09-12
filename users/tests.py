import base64
import hashlib
from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import SimpleTestCase
from django.urls import reverse
from django.utils import timezone

from bugsink.app_settings import get_settings, override_settings
from bugsink.test_utils import TransactionTestCase25251 as TransactionTestCase

from . import oidc
from .models import EmailVerification


User = get_user_model()


class EmailVerificationExpiryTestCase(TransactionTestCase):
    def _verification_for(self, email, age_seconds):
        user = User.objects.create_user(username=email, email=email, is_active=False)
        verification = EmailVerification.objects.create(user=user, email=email)
        EmailVerification.objects.filter(pk=verification.pk).update(
            created_at=timezone.now() - timedelta(seconds=age_seconds))
        return user, verification

    def test_recent_token_can_confirm_email(self):
        user, verification = self._verification_for("recent@example.com", 59)

        get_settings()
        with override_settings(USER_REGISTRATION_VERIFY_EMAIL_EXPIRY=60):
            response = self.client.post(reverse("confirm_email", kwargs={"token": verification.token}))

        self.assertEqual(response.status_code, 302)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))
        self.assertFalse(EmailVerification.objects.filter(pk=verification.pk).exists())

    def test_expired_token_cannot_confirm_email(self):
        user, verification = self._verification_for("expired-confirm@example.com", 61)

        get_settings()
        with override_settings(USER_REGISTRATION_VERIFY_EMAIL_EXPIRY=60):
            response = self.client.get(reverse("confirm_email", kwargs={"token": verification.token}))

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("_auth_user_id", self.client.session)
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    def test_expired_token_cannot_reset_password(self):
        user, verification = self._verification_for("expired-reset@example.com", 61)

        get_settings()
        with override_settings(USER_REGISTRATION_VERIFY_EMAIL_EXPIRY=60):
            response = self.client.get(reverse("reset_password", kwargs={"token": verification.token}))

        self.assertEqual(response.status_code, 404)
        self.assertFalse(user.has_usable_password())


class ResetPasswordRedirectTestCase(TransactionTestCase):
    def _verification_for(self, email="user@example.com"):
        user = User.objects.create_user(username=email, email=email, is_active=False)
        return EmailVerification.objects.create(user=user, email=email)

    def test_reset_password_rejects_external_next_redirect(self):
        verification = self._verification_for()

        response = self.client.post(
            reverse("reset_password", kwargs={"token": verification.token}),
            {
                "new_password1": "S3curePassw0rd!",
                "new_password2": "S3curePassw0rd!",
                "next": "https://evil.example/phish",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("home"))

    def test_reset_password_allows_local_next_redirect(self):
        verification = self._verification_for("local@example.com")

        response = self.client.post(
            reverse("reset_password", kwargs={"token": verification.token}),
            {
                "new_password1": "S3curePassw0rd!",
                "new_password2": "S3curePassw0rd!",
                "next": "/accounts/preferences/",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/accounts/preferences/")


class CreateSetPasswordLinkCommandTestCase(TransactionTestCase):
    def test_create_set_password_link_prints_reset_password_url(self):
        user = User.objects.create_user(username="command@example.com", email="command@example.com")

        stdout = StringIO()
        call_command("create_set_password_link", "command@example.com", stdout=stdout)

        verification = EmailVerification.objects.get(user=user)
        self.assertEqual(
            stdout.getvalue().strip(),
            get_settings().BASE_URL + reverse("reset_password", kwargs={"token": verification.token}),
        )


class PreferencesPasswordTestCase(TransactionTestCase):
    def test_change_password_page_can_change_own_password(self):
        user = User.objects.create_user(
            username="preferences@example.com",
            email="preferences@example.com",
            password="OldSecurePassw0rd!",
        )
        self.client.force_login(user)

        preferences_response = self.client.get(reverse("preferences"))
        self.assertContains(preferences_response, reverse("change_password"))

        response = self.client.post(reverse("change_password"), {
            "old_password": "OldSecurePassw0rd!",
            "new_password1": "NewSecurePassw0rd!",
            "new_password2": "NewSecurePassw0rd!",
        })

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("preferences"))

        user.refresh_from_db()
        self.assertTrue(user.check_password("NewSecurePassw0rd!"))
        self.assertEqual(self.client.get(reverse("preferences")).status_code, 200)


OIDC_SETTINGS = {
    "OIDC_DISCOVERY_URL": "https://idp.example.com/.well-known/openid-configuration",
    "OIDC_CLIENT_ID": "bugsink",
    "OIDC_CLIENT_SECRET": "s3cret",
}

PROVIDER_CONFIG = {
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
}


class FakeResponse:
    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code

    def json(self):
        return self.data


class OIDCUnitTestCase(SimpleTestCase):
    def test_discovery_url_is_completed_when_only_the_issuer_is_given(self):
        with override_settings(OIDC_DISCOVERY_URL="https://idp.example.com/", **{
                k: v for k, v in OIDC_SETTINGS.items() if k != "OIDC_DISCOVERY_URL"}):
            self.assertEqual(oidc.discovery_url(), "https://idp.example.com/.well-known/openid-configuration")

        with override_settings(**OIDC_SETTINGS):
            self.assertEqual(oidc.discovery_url(), OIDC_SETTINGS["OIDC_DISCOVERY_URL"])

    def test_pkce_challenge_is_the_url_safe_sha256_of_the_verifier(self):
        verifier, challenge = oidc.make_pkce_pair()

        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=")
        self.assertEqual(challenge, expected.decode("ascii"))
        self.assertNotIn("=", challenge)

    def test_is_enabled_needs_a_discovery_url(self):
        self.assertFalse(oidc.is_enabled())

        with override_settings(**OIDC_SETTINGS):
            self.assertTrue(oidc.is_enabled())


class OIDCLoginTestCase(TransactionTestCase):
    def setUp(self):
        super().setUp()
        oidc._discovery_cache.clear()
        oidc._discovery_cache[OIDC_SETTINGS["OIDC_DISCOVERY_URL"]] = PROVIDER_CONFIG

    def tearDown(self):
        oidc._discovery_cache.clear()
        super().tearDown()

    def _start_login(self, next_url=None):
        response = self.client.get(reverse("oidc_login"), {"next": next_url} if next_url else {})
        self.assertEqual(response.status_code, 302)
        return parse_qs(urlparse(response["Location"]).query)

    def _callback(self, params, email="oidc@example.com", email_verified=None):
        claims = {"email": email}
        if email_verified is not None:
            claims["email_verified"] = email_verified

        with patch("users.oidc.requests.request") as request:
            request.side_effect = [FakeResponse({"access_token": "at"}), FakeResponse(claims)]
            return self.client.get(reverse("oidc_callback"), params)

    def test_login_page_shows_the_password_form_when_oidc_is_not_configured(self):
        response = self.client.get(reverse("login"))

        self.assertContains(response, 'name="password"')
        self.assertNotContains(response, reverse("oidc_login"))

    def test_login_page_shows_a_single_oidc_button_when_oidc_is_configured(self):
        with override_settings(**OIDC_SETTINGS):
            response = self.client.get(reverse("login"))

        self.assertContains(response, reverse("oidc_login"))
        self.assertNotContains(response, 'name="password"')
        self.assertNotContains(response, reverse("request_reset_password"))

    def test_password_login_and_password_reset_are_disabled_when_oidc_is_configured(self):
        User.objects.create_user(username="oidc@example.com", email="oidc@example.com", password="S3curePassw0rd!")

        with override_settings(**OIDC_SETTINGS):
            response = self.client.post(
                reverse("login"), {"username": "oidc@example.com", "password": "S3curePassw0rd!"})
            self.assertEqual(response.status_code, 404)
            self.assertNotIn("_auth_user_id", self.client.session)

            self.assertEqual(self.client.get(reverse("request_reset_password")).status_code, 404)

    def test_oidc_views_are_not_available_when_oidc_is_not_configured(self):
        self.assertEqual(self.client.get(reverse("oidc_login")).status_code, 404)
        self.assertEqual(self.client.get(reverse("oidc_callback")).status_code, 404)

    def test_login_redirects_to_the_provider_with_state_and_pkce(self):
        with override_settings(**OIDC_SETTINGS):
            response = self.client.get(reverse("oidc_login"))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith(PROVIDER_CONFIG["authorization_endpoint"] + "?"))

        params = parse_qs(urlparse(response["Location"]).query)
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["client_id"], ["bugsink"])
        self.assertEqual(params["scope"], ["openid email"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(
            params["redirect_uri"], [get_settings().BASE_URL + reverse("oidc_callback")])
        self.assertEqual(params["state"], [self.client.session["oidc_state"]])

    def test_callback_logs_in_the_matching_user(self):
        user = User.objects.create_user(username="oidc@example.com", email="oidc@example.com")

        with override_settings(**OIDC_SETTINGS):
            params = self._start_login(next_url="/issues/")
            code_verifier = self.client.session["oidc_code_verifier"]

            with patch("users.oidc.requests.request") as request:
                request.side_effect = [
                    FakeResponse({"access_token": "at"}), FakeResponse({"email": "OIDC@Example.com"})]
                response = self.client.get(
                    reverse("oidc_callback"), {"code": "the-code", "state": params["state"][0]})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/issues/")
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))

        token_call, userinfo_call = request.call_args_list
        self.assertEqual(token_call.args, ("POST", PROVIDER_CONFIG["token_endpoint"]))
        self.assertEqual(token_call.kwargs["auth"], ("bugsink", "s3cret"))
        self.assertEqual(token_call.kwargs["data"], {
            "grant_type": "authorization_code",
            "code": "the-code",
            "redirect_uri": get_settings().BASE_URL + reverse("oidc_callback"),
            "code_verifier": code_verifier,
        })
        self.assertEqual(userinfo_call.args, ("GET", PROVIDER_CONFIG["userinfo_endpoint"]))
        self.assertEqual(userinfo_call.kwargs["headers"], {"Authorization": "Bearer at"})

    def test_callback_matches_an_account_whose_username_is_not_an_email(self):
        user = User.objects.create_user(username="admin", email="oidc@example.com")

        with override_settings(**OIDC_SETTINGS):
            params = self._start_login()
            response = self._callback({"code": "the-code", "state": params["state"][0]})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))

    def test_callback_ignores_an_off_site_next_url(self):
        User.objects.create_user(username="oidc@example.com", email="oidc@example.com")

        with override_settings(**OIDC_SETTINGS):
            params = self._start_login(next_url="https://evil.example/phish")
            response = self._callback({"code": "the-code", "state": params["state"][0]})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("home"))

    def test_callback_does_not_create_or_log_in_unknown_or_inactive_users(self):
        with override_settings(**OIDC_SETTINGS):
            params = self._start_login()
            response = self._callback({"code": "the-code", "state": params["state"][0]})

            self.assertEqual(response.status_code, 403)
            self.assertContains(response, "No active Bugsink account", status_code=403)
            self.assertNotIn("_auth_user_id", self.client.session)
            self.assertFalse(User.objects.filter(username="oidc@example.com").exists())

            User.objects.create_user(username="oidc@example.com", email="oidc@example.com", is_active=False)
            params = self._start_login()
            response = self._callback({"code": "the-code", "state": params["state"][0]})

            self.assertEqual(response.status_code, 403)
            self.assertNotIn("_auth_user_id", self.client.session)

    def test_callback_rejects_a_mismatched_state(self):
        User.objects.create_user(username="oidc@example.com", email="oidc@example.com")

        with override_settings(**OIDC_SETTINGS):
            self._start_login()
            response = self._callback({"code": "the-code", "state": "not-the-state"})

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_callback_rejects_an_unverified_email(self):
        User.objects.create_user(username="oidc@example.com", email="oidc@example.com")

        with override_settings(**OIDC_SETTINGS):
            params = self._start_login()
            response = self._callback({"code": "the-code", "state": params["state"][0]}, email_verified=False)

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_callback_reports_an_error_from_the_provider(self):
        with override_settings(**OIDC_SETTINGS):
            params = self._start_login()
            response = self.client.get(
                reverse("oidc_callback"), {"error": "access_denied", "state": params["state"][0]})

        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "refused the login request", status_code=403)
