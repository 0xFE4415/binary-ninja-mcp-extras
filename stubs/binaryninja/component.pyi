from binaryninja.function import Function


class Component:
    guid: str
    display_name: str
    name: str
    parent: Component | None
    components: list[Component]
    function_list: list[Function]

    def add_function(self, func: Function) -> bool: ...
    def contains_function(self, func: Function) -> bool: ...
    def remove_function(self, func: Function) -> bool: ...
