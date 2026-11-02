from typing import Any


class Component:
    guid: str
    display_name: str
    name: str
    parent: Component | None
    components: list[Component]
    function_list: list[Any]

    def add_function(self, function: Any) -> bool: ...
    def contains_function(self, function: Any) -> bool: ...
    def remove_function(self, function: Any) -> bool: ...
