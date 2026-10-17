from ca_gap_analyzer.auth import SCOPES, explain


def test_requests_only_read_scopes():
    assert all(scope.endswith(".Read.All") for scope in SCOPES)


def test_known_error_gets_a_fix():
    result = {
        "error": "invalid_client",
        "error_description": "AADSTS7000218: The request body must contain client_assertion or client_secret.\nTrace ID: x",
    }
    message = explain(result)
    assert "Mobile and desktop applications" in message
    assert "AADSTS7000218" in message
    assert "Trace ID" not in message  # only the first line of Entra's message


def test_unknown_error_passes_through():
    assert explain({"error": "something_new"}) == "Sign-in failed: something_new"
