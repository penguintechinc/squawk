"""Shared API response helpers.

Centralizes the error-response contract so internal exception detail
(paths, DB errors, library messages) is logged server-side and never
returned to clients.
"""

from __future__ import annotations

import logging
from typing import Tuple

from flask import jsonify, request

logger = logging.getLogger(__name__)


def internal_error(exc: Exception, message: str = "Internal server error") -> Tuple:
    """Log the exception with full detail; return a generic 500 to the client.

    Usage:
        except Exception as e:
            return internal_error(e)
    """
    logger.exception(
        "Unhandled error handling %s %s: %s", request.method, request.path, exc
    )
    return jsonify({"error": message}), 500
