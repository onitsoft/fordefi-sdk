JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
JsonList = list[JsonValue]
JsonDict = dict[str, JsonValue]
Json = JsonList | JsonDict
Headers = dict[str, str]
QueryParams = dict[str, str | int | list[str]]
