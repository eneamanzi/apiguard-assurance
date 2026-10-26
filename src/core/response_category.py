"""
src/core/response_category.py

The first step of every judgement: what a response is (ResponseCategory).

One rule for every test: a test never
lists status codes of its own; it asks for the category of a response and then
says, in its oracle, what that category means for its guarantee (an Outcome).

The categories follow RFC 9110 section 15 and the IANA HTTP Status Code
registry (https://www.iana.org/assignments/http-status-codes/, read
2026-10-20): every registered code belongs to one category, and a code the
registry does not list counts as the x00 code of its class, as RFC 9110
section 15 asks of a recipient that does not recognise a status code. No
response at all (timeout, refused connection, TLS error, reset) is
NO_RESPONSE.

The reference responses of a run (calibration, positive control) can correct
a misleading status, e.g. a 404 that is in fact a refusal; that correction is
built on top of this rule, which looks at the status alone.

Dependency rule: imports only from src.core.models.
"""

from __future__ import annotations

from src.core.models.enums import ResponseCategory

# Registered status codes (IANA) of each category whose codes are not a whole
# class. Codes of a category not listed here come from the class rule below.
_REDIRECT_CODES: frozenset[int] = frozenset({300, 301, 302, 303, 305, 307, 308})
_UNAUTHENTICATED_CODES: frozenset[int] = frozenset({401, 407, 511})
_FORBIDDEN_CODES: frozenset[int] = frozenset({403})
_NOT_FOUND_CODES: frozenset[int] = frozenset({404, 410})
_METHOD_NOT_ALLOWED_CODES: frozenset[int] = frozenset({405, 501})
_INVALID_REQUEST_CODES: frozenset[int] = frozenset(
    {400, 406, 409, 411, 412, 413, 414, 415, 416, 417, 421, 422, 423, 424, 425, 426, 428, 431}
)
_RATE_LIMITED_CODES: frozenset[int] = frozenset({429})
_SERVER_ERROR_CODES: frozenset[int] = frozenset({500, 505, 506, 507, 508, 510})
_UPSTREAM_UNAVAILABLE_CODES: frozenset[int] = frozenset({502, 503, 504})
# Registered but never decisive alone: 304 (Not Modified, an answer to a
# conditional request), 306 and 418 (Unused), 402 (Payment Required), 408
# (Request Timeout: the server gave up waiting for the request), 451
# (Unavailable For Legal Reasons). 1xx are informational and come from the
# class rule.
_OTHER_CODES: frozenset[int] = frozenset({304, 306, 402, 408, 418, 451})

_CATEGORY_OF_CODE: dict[int, ResponseCategory] = {
    code: category
    for codes, category in (
        (_REDIRECT_CODES, ResponseCategory.REDIRECT),
        (_UNAUTHENTICATED_CODES, ResponseCategory.UNAUTHENTICATED),
        (_FORBIDDEN_CODES, ResponseCategory.FORBIDDEN),
        (_NOT_FOUND_CODES, ResponseCategory.NOT_FOUND),
        (_METHOD_NOT_ALLOWED_CODES, ResponseCategory.METHOD_NOT_ALLOWED),
        (_INVALID_REQUEST_CODES, ResponseCategory.INVALID_REQUEST),
        (_RATE_LIMITED_CODES, ResponseCategory.RATE_LIMITED),
        (_SERVER_ERROR_CODES, ResponseCategory.SERVER_ERROR),
        (_UPSTREAM_UNAVAILABLE_CODES, ResponseCategory.UPSTREAM_UNAVAILABLE),
        (_OTHER_CODES, ResponseCategory.OTHER),
    )
    for code in codes
}

# The size of a status class (1xx, 2xx, ...): code // _CLASS_SIZE is its class.
_CLASS_SIZE: int = 100

# The category of a whole class, for the codes not listed above (every 2xx,
# every 1xx) and for unregistered codes, which count as the class's x00:
# 100 Continue, 200 OK, 300 Multiple Choices, 400 Bad Request,
# 500 Internal Server Error.
_CATEGORY_OF_CLASS: dict[int, ResponseCategory] = {
    1: ResponseCategory.OTHER,
    2: ResponseCategory.SERVED,
    3: ResponseCategory.REDIRECT,
    4: ResponseCategory.INVALID_REQUEST,
    5: ResponseCategory.SERVER_ERROR,
}


def categorize(status_code: int | None) -> ResponseCategory:
    """
    The category of a response, from its HTTP status alone.

    Args:
        status_code: The HTTP status of the response; None when no response
                     arrived (timeout, refused connection, TLS error, reset).

    Returns:
        NO_RESPONSE for None; the category of a registered code; for any other
        code, the category of its class's x00 code (RFC 9110 section 15);
        OTHER for a number outside the five classes.
    """
    if status_code is None:
        return ResponseCategory.NO_RESPONSE
    listed = _CATEGORY_OF_CODE.get(status_code)
    if listed is not None:
        return listed
    return _CATEGORY_OF_CLASS.get(status_code // _CLASS_SIZE, ResponseCategory.OTHER)
