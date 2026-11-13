import pytest


@pytest.fixture(autouse=True)
def forbid_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(seconds: float) -> None:
        raise AssertionError(f"unpatched time.sleep({seconds})")

    monkeypatch.setattr("time.sleep", refuse)
