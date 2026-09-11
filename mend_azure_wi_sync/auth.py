"""Entra service principal auth decisions, with no I/O.

Same contract as identity.py, reconcile.py, routing.py and enrichment.py: primitives in,
values out. The HTTP that uses any of this lives in core.py.

`now` parameters are ELAPSED-TIME readings (time.monotonic()), not wall clock. On a
self-hosted runner an NTP correction can step the wall clock mid-run, which would either
discard a good token or keep serving a dead one. Elapsed time is all this needs.
"""

# The fixed, global Azure DevOps resource ID. Identical in every tenant and every
# organization. The `https://app.vssps.visualstudio.com/.default` form resolves to the
# same resource; the GUID is preferred because it carries no ambiguity with the legacy
# visualstudio.com hostnames.
AZURE_DEVOPS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"

# Refresh this far before expiry. call_azure_api runs in tight loops and a full sync at
# this customer's scale spans well over an hour, so a token must never be handed out with
# only seconds left on it.
REFRESH_MARGIN_SECONDS = 300

_ENTRA_FIELD_NAMES = ("MEND_AZURETENANTID", "MEND_AZURECLIENTID", "MEND_AZURECLIENTSECRET")


def auth_mode(pat: str, tenant_id: str, client_id: str, client_secret: str) -> str:
    """"entra", "pat" or "none".

    A complete triple wins over a PAT: a migrating customer leaves the PAT in place, and
    the newer credential is the intended one. A partial triple is not a credential, so it
    never selects a mode on its own.
    """
    if tenant_id and client_id and client_secret:
        return "entra"
    if pat:
        return "pat"
    return "none"


def missing_entra_fields(tenant_id: str, client_id: str, client_secret: str) -> list:
    """The MEND_* names absent from a PARTIALLY configured triple.

    Empty for a complete triple and, deliberately, for a wholly absent one: an operator
    using a PAT must not be told to set three variables they never intended to set.
    """
    present = (bool(tenant_id), bool(client_id), bool(client_secret))
    if all(present) or not any(present):
        return []
    return [name for name, ok in zip(_ENTRA_FIELD_NAMES, present) if not ok]


def token_endpoint(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


def token_request_body(client_id: str, client_secret: str) -> dict:
    """The OAuth 2.0 client credentials form body.

    A future certificate credential replaces client_secret with a client_assertion pair
    here and changes nothing else in this module.
    """
    return {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"{AZURE_DEVOPS_RESOURCE}/.default",
    }


def parse_token_response(payload, now: float) -> tuple:
    """(token, expires_at) from a token response, ("", 0.0) if it carries no usable one.

    The deadline is floored at `now`: an expires_in below the refresh margin would
    otherwise produce a deadline in the past, so the token would be discarded on arrival
    and every single call would re-mint.
    """
    try:
        token = payload["access_token"]
        expires_in = int(payload.get("expires_in", 3600))
    except:
        return "", 0.0
    if not token:
        return "", 0.0
    return token, max(now + expires_in - REFRESH_MARGIN_SECONDS, now)


def token_is_fresh(cached_token: str, expires_at: float, now: float) -> bool:
    return bool(cached_token) and now < expires_at


def token_error_message(payload, text: str) -> str:
    """Entra's error_description if it has one, else the raw body.

    Takes only the RESPONSE. It must never be given a request value, or a failed auth
    would print the client secret into the pipeline log.
    """
    description = ""
    try:
        description = payload["error_description"]
    except:
        pass
    return description if description else text
