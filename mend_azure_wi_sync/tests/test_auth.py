"""Mode selection and token expiry maths, with no network anywhere.

These are the parts of Entra auth where the bugs live: a partially configured service
principal that silently falls back, a refresh deadline that lands in the past, a cached
token served after it died. All of it is arithmetic and string building, so all of it is
testable without a mock.
"""

import pytest

from mend_azure_wi_sync import auth

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
CLIENT = "11111111-2222-3333-4444-555555555555"
SECRET = "a-client-secret-value"


# ------------------------------------------------------------------ mode selection

def test_a_complete_triple_selects_entra():
    assert auth.auth_mode("", TENANT, CLIENT, SECRET) == "entra"


def test_a_pat_alone_selects_pat():
    assert auth.auth_mode("a-pat", "", "", "") == "pat"


def test_entra_wins_when_both_are_configured():
    """Migrating customers will leave the PAT in place. The newer credential is the
    intended one, and leaving it ambiguous would make behaviour depend on env ordering."""
    assert auth.auth_mode("a-pat", TENANT, CLIENT, SECRET) == "entra"


def test_nothing_configured_is_none():
    assert auth.auth_mode("", "", "", "") == "none"


def test_a_partial_triple_with_no_pat_is_none():
    """Must NOT fall through to a mode. There is no credential here."""
    assert auth.auth_mode("", TENANT, CLIENT, "") == "none"


def test_a_partial_triple_with_a_pat_stays_on_the_pat():
    """A half-finished migration must not break a working pipeline. check_patterns
    warns about it (Task 3); it is not an error."""
    assert auth.auth_mode("a-pat", TENANT, "", "") == "pat"


# ------------------------------------------------------------------ missing fields

def test_missing_fields_names_exactly_what_is_absent():
    assert auth.missing_entra_fields(TENANT, "", SECRET) == ["MEND_AZURECLIENTID"]
    assert auth.missing_entra_fields("", CLIENT, "") == [
        "MEND_AZURETENANTID", "MEND_AZURECLIENTSECRET"]


def test_a_complete_triple_is_missing_nothing():
    assert auth.missing_entra_fields(TENANT, CLIENT, SECRET) == []


def test_a_wholly_absent_triple_is_missing_nothing():
    """Absent is not partial. An operator using a PAT must not be told to set three
    variables they deliberately did not set."""
    assert auth.missing_entra_fields("", "", "") == []


# ------------------------------------------------------------------ request shape

def test_the_token_endpoint_is_tenant_scoped():
    assert auth.token_endpoint(TENANT) == (
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")


def test_the_body_is_client_credentials_scoped_to_azure_devops():
    body = auth.token_request_body(CLIENT, SECRET)
    assert body["grant_type"] == "client_credentials"
    assert body["client_id"] == CLIENT
    assert body["client_secret"] == SECRET
    assert body["scope"] == "499b84ac-1321-427f-aa17-267ca6975798/.default"


def test_the_resource_guid_is_the_fixed_global_azure_devops_id():
    """Identical in every tenant and organization. A per-tenant value here is a bug."""
    assert auth.AZURE_DEVOPS_RESOURCE == "499b84ac-1321-427f-aa17-267ca6975798"


# ------------------------------------------------------------------ response parsing

def test_a_good_response_yields_a_token_and_an_early_deadline():
    token, expires_at = auth.parse_token_response(
        {"access_token": "abc", "expires_in": 3599}, now=1000.0)
    assert token == "abc"
    assert expires_at == 1000.0 + 3599 - auth.REFRESH_MARGIN_SECONDS


def test_a_missing_expires_in_defaults_to_an_hour():
    _, expires_at = auth.parse_token_response({"access_token": "abc"}, now=0.0)
    assert expires_at == 3600 - auth.REFRESH_MARGIN_SECONDS


def test_a_short_lived_token_never_produces_a_past_deadline():
    """expires_in below the margin would otherwise make expires_at < now, so the token
    would be discarded the instant it arrived and every call would re-mint."""
    _, expires_at = auth.parse_token_response(
        {"access_token": "abc", "expires_in": 60}, now=500.0)
    assert expires_at == 500.0


def test_a_response_with_no_access_token_yields_nothing():
    assert auth.parse_token_response({"error": "invalid_client"}, now=0.0) == ("", 0.0)
    assert auth.parse_token_response({"access_token": ""}, now=0.0) == ("", 0.0)


def test_a_non_dict_payload_does_not_raise():
    assert auth.parse_token_response(None, now=0.0) == ("", 0.0)
    assert auth.parse_token_response("<html>502</html>", now=0.0) == ("", 0.0)


# ------------------------------------------------------------------ freshness

def test_a_token_is_fresh_before_its_deadline():
    assert auth.token_is_fresh("abc", expires_at=100.0, now=99.9) is True


def test_a_token_is_stale_at_and_after_its_deadline():
    assert auth.token_is_fresh("abc", expires_at=100.0, now=100.0) is False
    assert auth.token_is_fresh("abc", expires_at=100.0, now=100.1) is False


def test_an_empty_token_is_never_fresh():
    assert auth.token_is_fresh("", expires_at=1e9, now=0.0) is False


# ------------------------------------------------------------------ error text

def test_the_error_message_prefers_entras_description():
    msg = auth.token_error_message(
        {"error": "invalid_client",
         "error_description": "AADSTS7000215: Invalid client secret provided."}, "raw body")
    assert "AADSTS7000215" in msg


def test_the_error_message_falls_back_to_the_raw_body():
    assert auth.token_error_message({}, "502 Bad Gateway") == "502 Bad Gateway"
    assert auth.token_error_message(None, "502 Bad Gateway") == "502 Bad Gateway"


def test_the_error_message_cannot_echo_the_secret():
    """It only ever sees the response. If this signature ever grows a request argument,
    a failed auth would print the credential into the pipeline log."""
    import inspect
    params = list(inspect.signature(auth.token_error_message).parameters)
    assert params == ["payload", "text"]
