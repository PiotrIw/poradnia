from __future__ import annotations

import logging

from django.conf import settings
from django.shortcuts import redirect
from django.urls import resolve, reverse


AUTH_METHODS_SESSION_KEY = "account_authentication_methods"


logger = logging.getLogger(__name__)


def _get_auth_method_types(request) -> set[str]:
    """
    allauth stores a list of dicts in session, e.g.:
      [{"type": "password"}, {"type": "totp"}]
    """
    methods = request.session.get(AUTH_METHODS_SESSION_KEY, []) or []
    out: set[str] = set()
    for m in methods:
        if isinstance(m, dict):
            t = m.get("method")
            if isinstance(t, str):
                out.add(t)
    return out


class EnforceStaffMfaOnPasswordLoginMiddleware:
    """
    Policy:
      - If user is staff/superuser AND session indicates password was used,
        require MFA completion (TOTP/recovery codes) before allowing access.
      - If user authenticated via social login only (e.g., Google), do NOT require allauth MFA.

    Notes:
      - Prevent redirect loops by exempting allauth account + mfa endpoints.
      - One can further scope enforcement to /admin/ only if desired.
    """

    # URL names we allow even if MFA not completed (avoid loops)
    EXEMPT_URL_NAMES: set[str] = {
        # core allauth
        "account_login",
        "account_logout",
        "account_signup",
        "account_reset_password",
        "account_reset_password_done",
        "account_reset_password_from_key",
        "account_reset_password_from_key_done",
        # allauth mfa
        "mfa_index",
        "mfa_authenticate",
        "mfa_reauthenticate",
        "mfa_activate_totp",
        "mfa_deactivate_totp",
        "mfa_generate_recovery_codes",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip if not authenticated
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return self.get_response(request)

        # Only enforce for staff/superuser
        if not (user.is_staff or user.is_superuser):
            return self.get_response(request)

        # Exempt static/media and exempt url names
        if request.path.startswith(getattr(settings, "STATIC_URL", "/static/")):
            return self.get_response(request)
        if request.path.startswith(getattr(settings, "MEDIA_URL", "/media/")):
            return self.get_response(request)
        if request.path in ("/favicon.ico", "/robots.txt"):
            return self.get_response(request)

        try:
            match = resolve(request.path_info)
            if match.url_name in self.EXEMPT_URL_NAMES:
                return self.get_response(request)
        except Exception:
            # If resolve fails for some reason, fall through to enforcement
            pass

        auth_method_types = _get_auth_method_types(request)

        # If the login did NOT involve a password (e.g. Google social login),
        # allow access without allauth MFA.
        if "password" not in auth_method_types and "socialaccount" in auth_method_types:
            return self.get_response(request)

        # If password was used, require MFA completion.
        # Depending on factors, session may record "totp" (and/or "recovery_codes").
        if "password" in auth_method_types:
            mfa_done = bool(
                auth_method_types.intersection({"totp", "recovery_codes", "mfa"})
            )
            if not mfa_done:
                logger.debug(
                    "AUTH_METHODS: %s",
                    request.session.get("account_authentication_methods"),
                )
                logger.debug(
                    "SOCIAL_FLAG: %s", request.session.get("poradnia_auth_via_social")
                )
                logger.debug("PATH: %s", request.path)
                return redirect(reverse("mfa_index"))

        return self.get_response(request)
