class FileMetadata:
    filename: str
    modified: bool
    saved: bool

    def close(self) -> None: ...
    undo_entries: list[Any]
    redo_entries: list[Any]

    def undo(self) -> None: ...
    def redo(self) -> None: ...
