class FileMetadata:
    filename: str
    modified: bool
    saved: bool

    def close(self) -> None: ...
