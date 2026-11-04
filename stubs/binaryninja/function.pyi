from typing import Any


class Function:
    name: str
    start: int
    end: int
    callers: list[Function]
    callees: list[Function]
    hlil: Any
    mlil: Any
    comment: str
    basic_blocks: Any

    def set_user_type(self, value: Any) -> None: ...
