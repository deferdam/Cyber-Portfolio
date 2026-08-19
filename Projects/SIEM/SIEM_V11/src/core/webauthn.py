"""FIDO2/WebAuthn (hardware key, e.g. YubiKey) via python-fido2.

Unlike TOTP, WebAuthn is NOT hand-rolled: the protocol involves CBOR/COSE parsing,
attestation verification, and signature counters, with real security pitfalls if
implemented incorrectly. python-fido2 is maintained by Yubico, the reference
implementation; using it here is the responsible choice, the mirror image of the TOTP
decision where hand-rolling was safe because the RFC is short and self-verifying.

Security properties this buys us, compared to TOTP:
  * The private key never leaves the authenticator (YubiKey). The server stores only a
    public key and a credential id; stealing the accounts DB gives an attacker nothing
    that lets them impersonate the key (unlike a stolen TOTP shared secret).
  * Signatures are cryptographically bound to the origin (rp_id). A phishing site
    cannot obtain a valid signature even if the user is fooled, because the browser
    itself refuses to sign for the wrong origin.

Secure context requirement: WebAuthn only works over HTTPS, OR over http://localhost /
http://127.0.0.1 (browsers treat loopback as already secure). The launcher binds
127.0.0.1 by default, so this works out of the box for local use; it will NOT work if
the app is reached via a LAN IP or hostname without TLS.
"""
from __future__ import annotations

import os

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

# WebAuthn is strict about the relying party id: when the browser's origin host is an IP
# address, rp_id must be EXACTLY that IP (not a hostname like "localhost"), per the spec.
# launch.py opens http://127.0.0.1:5000 by default, so RP_ID must be "127.0.0.1" to match.
# Overridable via SIEM_WEBAUTHN_RP_ID for deployments that use a real hostname + TLS.
RP_ID = os.environ.get("SIEM_WEBAUTHN_RP_ID", "127.0.0.1")
RP_NAME = "Mini SOAR"


def _server() -> Fido2Server:
    rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
    return Fido2Server(rp)


def registration_begin(username: str, existing_credentials: list) -> tuple:
    """Start enrollment of a new key. `existing_credentials` is a list of
    AttestedCredentialData already registered for this user, so the same key cannot be
    registered twice and the browser can skip an already-enrolled authenticator.
    Returns (options_json_dict, state) - state must be kept server-side (session) until
    registration_complete."""
    server = _server()
    user = PublicKeyCredentialUserEntity(
        id=username.encode("utf-8"), name=username, display_name=username)
    options, state = server.register_begin(
        user, credentials=existing_credentials,
        user_verification=UserVerificationRequirement.PREFERRED)
    return dict(options), state


def registration_complete(state, response: dict) -> AttestedCredentialData:
    """Finish enrollment: verify the browser's attestation response against the
    challenge in `state`. Raises on any verification failure (bad signature, wrong
    origin, replayed challenge). Returns the credential to store."""
    server = _server()
    auth_data = server.register_complete(state, response)
    return auth_data.credential_data


def authentication_begin(credentials: list) -> tuple:
    """Start a login/verification ceremony against a set of already-enrolled
    AttestedCredentialData. Returns (options_json_dict, state)."""
    server = _server()
    options, state = server.authenticate_begin(
        credentials, user_verification=UserVerificationRequirement.PREFERRED)
    return dict(options), state


def authentication_complete(state, credentials: list, response: dict) -> AttestedCredentialData:
    """Finish a login ceremony: verify the signature against the stored public key and
    the challenge in `state`. Raises on any verification failure. Returns the specific
    credential that was used, so the caller can update its usage bookkeeping."""
    server = _server()
    return server.authenticate_complete(state, credentials, response)


class WebauthnUnavailable(Exception):
    """No USB security key was found plugged into this machine."""


def _cli_origin_verify(rp_id: str, origin: str) -> bool:
    """Custom origin check for the NATIVE CLI ceremony only (not the browser path).

    python-fido2's own default verify_rp_id() only special-cases the exact hostname
    'localhost' as a secure http:// origin; it does NOT allow 127.0.0.1, even though
    browsers do (loopback IPs are secure contexts per the W3C spec). Since this native
    path talks directly to a USB device over CTAP HID with no browser involved, there is
    no page-origin trust decision to defer to: the "origin" string here is just an
    internal label this process constructs for itself, verified only against our own
    fixed RP_ID. We accept it exactly when the host equals RP_ID, whether that is
    'localhost' or the loopback IP the launcher actually binds to.
    """
    from urllib.parse import urlparse
    host = urlparse(origin).hostname
    return host == rp_id


def cli_verify_key(credentials: list, prompt=print) -> bool:
    """Native (non-browser) WebAuthn verification for the CLI reset path: talks to a
    USB security key directly over CTAP HID, no browser involved. This is the gate for
    'reset-admin-password': machine access alone will not be enough once a key is
    enrolled, the physical key must also be presented and touched.

    Returns True if a valid signature was produced by one of the given credentials.
    Raises WebauthnUnavailable if no compatible USB key is plugged in.
    """
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, UserInteraction, DefaultClientDataCollector
    from fido2.webauthn import (
        PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise WebauthnUnavailable(
            "No USB security key detected. Plug in your YubiKey and try again.")

    class _Interaction(UserInteraction):
        def prompt_up(self):
            prompt("Touch your security key now...")

    origin = "http://%s" % RP_ID
    collector = DefaultClientDataCollector(origin, verify=_cli_origin_verify)

    options, state = authentication_begin(credentials)
    request_options = PublicKeyCredentialRequestOptions(
        challenge=state["challenge"],
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY,
                                          id=c.credential_id)
            for c in credentials
        ],
        timeout=30000,
    )

    for dev in devices:
        try:
            client = Fido2Client(dev, collector, user_interaction=_Interaction())
            selection = client.get_assertion(request_options)
            assertion = selection.get_response(0)
            response = {
                "id": assertion.credential_id.hex(),
                "response": {
                    "clientDataJSON": bytes(assertion.client_data),
                    "authenticatorData": bytes(assertion.authenticator_data),
                    "signature": assertion.signature,
                    "userHandle": assertion.user_handle,
                },
            }
            authentication_complete(state, credentials, response)
            return True
        except Exception:
            continue  # try the next plugged-in device, if more than one is present
    return False
