Primitive = str | int | float | bool | None
JsonValue = Primitive | list["JsonValue"] | dict[str, "JsonValue"]
Json = dict[str, JsonValue]
