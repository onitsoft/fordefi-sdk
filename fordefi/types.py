JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
JsonList = list[JsonValue]
JsonDict = dict[str, JsonValue]
Json = JsonList | JsonDict
