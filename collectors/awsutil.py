"""Shared AWS session for the collectors. Read-only profile only; turns an expired SSO login
into one clear sentence instead of a crash."""
from __future__ import annotations

import boto3
import botocore.exceptions as bx

import config

EXPIRED = f"AWS login expired, run: aws sso login --profile {config.AWS_PROFILE or 'siem-readonly'}"
LOGIN_ERRORS = tuple(getattr(bx, n) for n in ("SSOTokenLoadError", "UnauthorizedSSOTokenError", "TokenRetrievalError",
                                               "SSOError", "NoCredentialsError") if hasattr(bx, n))


def session():
    if config.AWS_PROFILE and "change" in config.AWS_PROFILE.lower():
        raise RuntimeError("Watchtower must use a read-only AWS profile")
    return boto3.Session(profile_name=config.AWS_PROFILE, region_name=config.AWS_REGION)


def explain(exc: Exception) -> str:
    if isinstance(exc, LOGIN_ERRORS):
        return EXPIRED
    if isinstance(exc, bx.ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException", "InvalidClientTokenId"):
            return EXPIRED
        return f"{code}: {exc.response.get('Error', {}).get('Message', '')}"[:300]
    return f"{type(exc).__name__}: {exc}"[:300]
