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

    def set_user_type(self, value: Any) -> None: ...
