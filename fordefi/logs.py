from typing import Any, Optional


def request_repr(
    method: str,
    path: str,
    query_params: Optional[dict[str, str]],
    headers: dict[str, str],
    body: Optional[dict[str, Any]],
    sensitive_headers: Optional[set[str]] = None,
) -> str:
    if sensitive_headers is None:
        sensitive_headers = set()

    return str(
        {
            "method": method,
            "path": path,
            "query": query_params,
            "headers": masked_headers(headers, sensitive_headers),
            "body": body,
        }
    )


def masked_headers(
    headers: dict[str, str], sensitive_headers: set[str]
) -> dict[str, str]:
    return {
        header: masked_header_value(header, value, sensitive_headers)
        for header, value in headers.items()
    }


def masked_header_value(header: str, value: str | bytes, sensitive_headers) -> str:
    if isinstance(value, bytes):
        value = value.decode()

    if header in sensitive_headers:
        length = len(value)
        begin = value[:10]
        return f"{begin}*** ({length} chars)"

    else:
        return value
