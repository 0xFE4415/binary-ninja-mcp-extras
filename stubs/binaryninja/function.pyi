from typing import Any

from binaryninja.mediumlevelil import MediumLevelILFunction
from binaryninja.variable import ArchAndAddr, PossibleValueSet, Variable


class Function:
    name: str
    start: int
    end: int
    callers: list[Function]
    callees: list[Function]
    hlil: Any
    mlil: MediumLevelILFunction | None
    comment: str
    basic_blocks: Any
    vars: list[Variable]

    def set_user_type(self, value: Any) -> None: ...
    def set_user_var_value(
        self, var: Variable, def_addr: int, value: PossibleValueSet, after: bool = True
    ) -> None: ...
    def get_all_user_var_values(self) -> dict[Variable, dict[ArchAndAddr, PossibleValueSet]]: ...
    def clear_user_var_value(self, var: Variable, def_addr: int, after: bool = True) -> None: ...
    def clear_all_user_var_values(self) -> None: ...
