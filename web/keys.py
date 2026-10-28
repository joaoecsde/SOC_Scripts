"""The only place API keys are read from a submitted form."""
from __future__ import annotations


def keys_from_form(form) -> dict:
    """Return the API keys typed into the form.

    Args:
        form: A mapping with ``get`` (such as ``request.form``).

    Returns:
        ``{"abuseipdb": str, "virustotal": str}``, stripped; empty when not given.
    """
    return {"abuseipdb": form.get("abuseipdb_key", "").strip(),
            "virustotal": form.get("virustotal_key", "").strip()}
