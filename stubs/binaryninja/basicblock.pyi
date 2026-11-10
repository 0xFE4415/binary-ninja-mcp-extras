from binaryninja.function import DisassemblySettings, DisassemblyTextLine


class BasicBlock:
    def get_disassembly_text(
        self, settings: DisassemblySettings | None = None
    ) -> list[DisassemblyTextLine]: ...
