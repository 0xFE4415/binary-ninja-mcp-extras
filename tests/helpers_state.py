"""Fake view state: tags in every scope and the metadata store."""

from __future__ import annotations

import types


class FakeTag:
    def __init__(self, type_name: str, data: str, scope: str = "data") -> None:
        self.data = data
        self.scope = scope
        self._type_name = type_name

    @property
    def type(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(name=self._type_name)


class FakeStateMixin:
    def _init_state(self) -> None:
        self._metadata: dict[str, object] = {}
        self._tags: list[tuple[int, FakeTag]] = []

    def add_tag(self, address: int, tag_type_name: str, data: str) -> None:
        self.add_scoped_tag("data", address, tag_type_name, data)

    def add_scoped_tag(self, scope: str, address: int, tag_type_name: str, data: str) -> None:
        self._tags.append((address, FakeTag(tag_type_name, data, scope)))

    def _tags_in(self, scope: str) -> list[tuple[int, FakeTag]]:
        return [(address, tag) for address, tag in self._tags if tag.scope == scope]

    def get_tags(self) -> list[tuple[int, FakeTag]]:
        return self._tags_in("data")

    @property
    def tags_for_data(self) -> list[tuple[int, FakeTag]]:
        return self._tags_in("data")

    @property
    def tags_for_address(self) -> list[tuple[int, FakeTag]]:
        return self._tags_in("address")

    @property
    def tags_for_function(self) -> list[tuple[int, FakeTag]]:
        return self._tags_in("function")

    @property
    def metadata(self) -> dict[str, object]:
        return dict(self._metadata)

    def store_metadata(self, key: str, value: object) -> None:
        self._metadata[key] = value

    def query_metadata(self, key: str) -> object:
        if key not in self._metadata:
            raise KeyError(key)
        return self._metadata[key]

    def remove_metadata(self, key: str) -> None:
        self._metadata.pop(key, None)
