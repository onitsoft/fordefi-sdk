from fordefi.logs import request_repr


def test_request_repr() -> None:
    method = "GET"
    path = "/vaults"
    query_params = {"page": "1"}
    headers = {
        "Authorization": "Bearer 123456",
        "Content-Type": "application/json",
    }
    body = None
    sensitive_headers = {"Authorization"}
    result = request_repr(
        method=method,
        path=path,
        query_params=query_params,
        headers=headers,
        body=body,
        sensitive_headers=sensitive_headers,
    )
    assert (
        result
        == "{'method': 'GET', 'path': '/vaults', 'query': {'page': '1'}, 'headers': {'Authorization': 'Bearer 123*** (13 chars)', 'Content-Type': 'application/json'}, 'body': None}"
    )

    result = request_repr(
        method=method,
        path=path,
        query_params=query_params,
        headers=headers,
        body=body,
        sensitive_headers=None,
    )
    assert (
        result
        == "{'method': 'GET', 'path': '/vaults', 'query': {'page': '1'}, 'headers': {'Authorization': 'Bearer 123456', 'Content-Type': 'application/json'}, 'body': None}"
    )
