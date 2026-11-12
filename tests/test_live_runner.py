import hashlib
import json
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import Any, cast, override

import pytest
import run_playbook as runner

RUNNER_PATH = Path(runner.__file__).resolve()
TOOL_REPLY_TIMEOUT_SECONDS = 5

ToolHandler = Callable[[dict[str, Any]], str | None]


def structured(data: dict[str, Any], is_error: bool = False) -> str:
    result = {"structuredContent": data, "isError": is_error, "content": []}
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result})


def drop_connection(arguments: dict[str, Any]) -> None:
    return None


class StubHandler(BaseHTTPRequestHandler):
    @override
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def send_body(self, body: str, status: int = 200) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        stub = cast(StubServer, self.server)
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = payload.get("method")
        if method == "initialize":
            self.send_body(stub.initialize_body)
            return
        if method != "tools/call":
            self.send_body("", 202)
            return
        name = payload["params"]["name"]
        arguments = payload["params"]["arguments"]
        stub.calls.append((name, arguments))
        handler = stub.tools.get(name)
        if handler is None:
            self.send_body(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}}))
            return
        body = handler(arguments)
        if body is None:
            self.close_connection = True
            return
        self.send_body(body)


class StubServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), StubHandler)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.tools: dict[str, ToolHandler] = {}
        self.initialize_body = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {}})

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"

    def call_names(self) -> list[str]:
        return [name for name, _ in self.calls]


@pytest.fixture
def stub() -> Iterator[StubServer]:
    server = StubServer()
    server.tools["bn_binary_open"] = lambda arguments: structured({"binary": {"handle": "h1"}})
    server.tools["rex_analysis_wait"] = lambda arguments: structured({"completed": True})
    server.tools["rex_eval_python"] = lambda arguments: structured(
        {"error": None, "result": "'1.0'"}
    )
    server.tools["rex_binary_close"] = lambda arguments: structured({"closed": True})
    server.tools["probe"] = lambda arguments: structured({"value": 1})
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture(autouse=True)
def restored_signals() -> Iterator[None]:
    handlers = {number: signal.getsignal(number) for number in runner.UNWIND_SIGNALS}
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    yield
    for number in runner.UNWIND_SIGNALS:
        signal.signal(number, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    for number, handler in handlers.items():
        signal.signal(number, handler)


@pytest.fixture
def fixture_file(tmp_path: Path) -> Path:
    path = tmp_path / "fixture.bin"
    path.write_bytes(b"fixture bytes")
    return path


def write_playbook(
    tmp_path: Path, fixture_file: Path, steps: list[dict[str, Any]], version: str = "1.0"
) -> Path:
    playbook = {
        "binary_ninja_version": version,
        "fixture": {
            "path": str(fixture_file),
            "sha256": hashlib.sha256(fixture_file.read_bytes()).hexdigest(),
        },
        "steps": steps,
    }
    path = tmp_path / "playbook.json"
    path.write_text(json.dumps(playbook))
    return path


def probe_step(step_id: str, expected_value: int) -> dict[str, Any]:
    return {
        "id": step_id,
        "guards": "guard text",
        "tool": "probe",
        "args": {},
        "expect": [{"kind": "subset", "path": "value", "value": expected_value}],
    }


def unused_client() -> runner.McpClient:
    return runner.McpClient("http://unused.invalid/mcp")


VALUE_CASES: list[tuple[dict[str, Any], Any, str | None]] = [
    ({"kind": "subset", "path": "", "value": {"a": 1}}, {"a": 1, "b": 2}, None),
    ({"kind": "subset", "path": "rows.0", "value": {"a": 1}}, {"rows": [{"a": 1, "b": 2}]}, None),
    ({"kind": "subset", "path": "", "value": {"a": 1}}, {"b": 2}, "$.a: missing"),
    ({"kind": "subset", "path": "", "value": {"a": 1}}, {"a": True}, "expected 1, got True"),
    ({"kind": "subset", "path": "", "value": {"a": [1]}}, {"a": [1, 2]}, "expected a list of 1"),
    ({"kind": "subset", "path": "", "value": {"a": [1, 2]}}, {"a": [1, 3]}, "$.a[1]"),
    ({"kind": "subset", "path": "", "value": {"a": {"b": 1}}}, {"a": 5}, "expected an object"),
    ({"kind": "contains", "path": "", "text": "ell"}, "hello", None),
    ({"kind": "contains", "path": "", "text": "ell"}, {"word": "hello"}, None),
    ({"kind": "contains", "path": "", "text": "xyz"}, "hello", "not found"),
    ({"kind": "not_contains", "path": "", "text": "xyz"}, "hello", None),
    ({"kind": "not_contains", "path": "", "text": "ell"}, "hello", "forbidden text"),
    ({"kind": "regex", "path": "", "pattern": "^h.llo$"}, "hello", None),
    ({"kind": "regex", "path": "", "pattern": "^x"}, "hello", "did not match"),
    ({"kind": "regex", "path": "", "pattern": "1"}, 1, "expected a string"),
    ({"kind": "not_regex", "path": "", "pattern": "^x"}, "hello", None),
    ({"kind": "not_regex", "path": "", "pattern": "^h"}, "hello", "forbidden regex"),
    ({"kind": "includes", "path": "", "item": {"a": 1}}, [{"a": 2}, {"a": 1, "b": 3}], None),
    ({"kind": "includes", "path": "", "item": {"a": 1}}, [{"a": 2}], "no element matches"),
    ({"kind": "includes", "path": "", "item": 1}, "text", "expected a list, got"),
    ({"kind": "excludes", "path": "", "item": {"a": 1}}, [{"a": 2}], None),
    ({"kind": "excludes", "path": "", "item": {"a": 1}}, [{"a": 2}, {"a": 1}], "index 1"),
    ({"kind": "length", "path": "", "value": 2}, [1, 2], None),
    ({"kind": "length", "path": "", "value": 2}, [1], "expected a list of 2"),
    ({"kind": "length", "path": "", "value": 2}, "ab", "expected a list of 2"),
    ({"kind": "unique", "path": ""}, [1, 2, {"a": 1}], None),
    ({"kind": "unique", "path": ""}, [1, 2, 1], "duplicate element 1"),
    ({"kind": "unique", "path": ""}, "ab", "expected a list"),
    ({"kind": "sorted_hex", "path": ""}, ["0x10", "0x20", "0x20"], None),
    ({"kind": "sorted_hex", "path": ""}, ["0x20", "0x10"], "not ascending"),
    ({"kind": "sorted_hex", "path": ""}, "0x10", "expected a list"),
    ({"kind": "sorted_hex", "path": ""}, ["nothex"], "ValueError"),
    ({"kind": "sorted_hex", "path": ""}, [16], "TypeError"),
    ({"kind": "length", "path": "missing", "value": 1}, {"present": [1]}, "KeyError"),
    ({"kind": "length", "path": "rows.5", "value": 1}, {"rows": [[1]]}, "missing at '5'"),
    ({"kind": "no_such_kind", "path": ""}, {}, "unknown expect kind"),
]


@pytest.mark.parametrize(("assertion", "data", "expected_reason"), VALUE_CASES)
def test_value_assertions(assertion: dict[str, Any], data: Any, expected_reason: str | None):
    reason = runner.run_assertion(assertion, runner.ToolResult(False, data), unused_client())
    if expected_reason is None:
        assert reason is None
        return
    assert reason is not None
    assert expected_reason in reason


def test_value_assertion_fails_when_the_tool_returned_an_error():
    assertion = {"kind": "subset", "path": "", "value": {}}
    reason = runner.run_assertion(
        assertion, runner.ToolResult(True, {"errorCode": "boom"}), unused_client()
    )
    assert reason is not None
    assert "tool returned an error" in reason


ERROR_CASES: list[tuple[dict[str, Any], bool, dict[str, Any], str | None]] = [
    ({"kind": "error_code", "code": "bad"}, True, {"errorCode": "bad"}, None),
    ({"kind": "error_code", "code": "bad"}, True, {"errorCode": "other"}, "got 'other'"),
    ({"kind": "error_code", "code": "bad"}, False, {"value": 1}, "got success"),
    (
        {"kind": "error_code", "code": "bad", "message_contains": "alpha"},
        True,
        {"errorCode": "bad", "errorMessage": "alpha beta"},
        None,
    ),
    (
        {"kind": "error_code", "code": "bad", "message_contains": "gamma"},
        True,
        {"errorCode": "bad", "errorMessage": "alpha beta"},
        "lacks 'gamma'",
    ),
    (
        {"kind": "error_code", "code": "bad", "message_lacks": "gamma"},
        True,
        {"errorCode": "bad", "errorMessage": "alpha beta"},
        None,
    ),
    (
        {"kind": "error_code", "code": "bad", "message_lacks": "beta"},
        True,
        {"errorCode": "bad", "errorMessage": "alpha beta"},
        "forbidden text 'beta'",
    ),
]


@pytest.mark.parametrize(("assertion", "is_error", "data", "expected_reason"), ERROR_CASES)
def test_error_code_assertion(
    assertion: dict[str, Any], is_error: bool, data: dict[str, Any], expected_reason: str | None
):
    reason = runner.run_assertion(assertion, runner.ToolResult(is_error, data), unused_client())
    if expected_reason is None:
        assert reason is None
        return
    assert reason is not None
    assert expected_reason in reason


def parity_step(expect_error: bool | None, fields: list[str], path: str = "") -> dict[str, Any]:
    assertion: dict[str, Any] = {
        "kind": "parity",
        "against": {"tool": "other", "args": {"pattern": "p"}},
        "fields": fields,
        "path": path,
    }
    if expect_error is not None:
        assertion["expect_error"] = expect_error
    return {"tool": "probe", "args": {}, "expect": [assertion]}


def run_parity(stub: StubServer, step: dict[str, Any]) -> list[str]:
    client = runner.McpClient(stub.url)
    client.initialize()
    return runner.run_step(step, "h1", client)


def test_parity_passes_when_both_succeed_with_equal_fields(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"total": 2, "extra": 1})
    stub.tools["other"] = lambda arguments: structured({"total": 2, "extra": 9})
    assert run_parity(stub, parity_step(None, ["total"])) == []
    assert stub.calls[-1] == ("other", {"binary": "h1", "pattern": "p"})


def test_parity_fails_when_fields_differ(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"total": 2})
    stub.tools["other"] = lambda arguments: structured({"total": 3})
    failures = run_parity(stub, parity_step(None, ["total"]))
    assert len(failures) == 1
    assert "differs from other" in failures[0]


def test_parity_fails_when_only_one_side_errors(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"total": 2})
    stub.tools["other"] = lambda arguments: structured({"errorCode": "x"}, True)
    failures = run_parity(stub, parity_step(None, ["total"]))
    assert len(failures) == 1
    assert "error=True differs from error=False" in failures[0]


def test_parity_rejects_both_erroring_without_expect_error(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"errorCode": "x"}, True)
    stub.tools["other"] = lambda arguments: structured({"errorCode": "x"}, True)
    failures = run_parity(stub, parity_step(None, ["errorCode"]))
    assert len(failures) == 1
    assert "both returned errors, but the step expects success" in failures[0]


def test_parity_rejects_both_succeeding_with_expect_error(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"total": 2})
    stub.tools["other"] = lambda arguments: structured({"total": 2})
    failures = run_parity(stub, parity_step(True, ["total"]))
    assert len(failures) == 1
    assert "both succeeded, but the step expects errors" in failures[0]


def test_parity_accepts_equal_errors_when_expected(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"errorCode": "x"}, True)
    stub.tools["other"] = lambda arguments: structured({"errorCode": "x"}, True)
    assert run_parity(stub, parity_step(True, ["errorCode"])) == []


def test_parity_rejects_different_errors_when_expected(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"errorCode": "x"}, True)
    stub.tools["other"] = lambda arguments: structured({"errorCode": "y"}, True)
    failures = run_parity(stub, parity_step(True, ["errorCode"]))
    assert len(failures) == 1
    assert "differs from other" in failures[0]


def test_parity_reads_the_step_side_at_its_path(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"results": [{}, {"total": 4}]})
    stub.tools["other"] = lambda arguments: structured({"total": 4})
    assert run_parity(stub, parity_step(None, ["total"], "results.1")) == []


def test_parity_with_a_missing_field_is_a_step_failure(stub: StubServer):
    stub.tools["probe"] = lambda arguments: structured({"total": 2})
    stub.tools["other"] = lambda arguments: structured({"total": 2})
    failures = run_parity(stub, parity_step(None, ["absent"]))
    assert len(failures) == 1
    assert failures[0].startswith("parity: KeyError")


def test_missing_path_is_a_step_failure_not_a_crash(stub: StubServer):
    step = probe_step("missing-path", 1)
    step["expect"][0]["path"] = "no.such.path"
    client = runner.McpClient(stub.url)
    client.initialize()
    failures = runner.run_step(step, "h1", client)
    assert len(failures) == 1
    assert "KeyError" in failures[0]
    assert "no.such.path" in failures[0]


def test_run_steps_reports_failures_and_counts_them(
    stub: StubServer, capsys: pytest.CaptureFixture[str]
):
    playbook = {"steps": [probe_step("good", 1), probe_step("bad", 2)]}
    client = runner.McpClient(stub.url)
    client.initialize()
    assert runner.run_steps(playbook, "h1", client) == 1
    output = capsys.readouterr().out
    assert "PASS good" in output
    assert "FAIL bad" in output
    assert "guards: guard text" in output


def test_run_steps_labels_only_non_harness_errors_unexpected(
    stub: StubServer, capsys: pytest.CaptureFixture[str]
):
    broken_step = {"id": "broken", "guards": "g", "tool": "probe", "args": {}}
    unknown_tool_step = {**probe_step("unknown-tool", 1), "tool": "unregistered"}
    playbook = {"steps": [broken_step, unknown_tool_step]}
    client = runner.McpClient(stub.url)
    client.initialize()
    assert runner.run_steps(playbook, "h1", client) == 2
    output = capsys.readouterr().out
    assert "unexpected KeyError" in output
    assert "HarnessError: unregistered: protocol error" in output
    assert "unexpected HarnessError" not in output


MALFORMED_REPLIES = [
    pytest.param("", id="empty-body"),
    pytest.param("{not json", id="invalid-json"),
    pytest.param("[1, 2]", id="not-an-object"),
    pytest.param('{"jsonrpc": "2.0", "id": 1}', id="no-result"),
    pytest.param('{"jsonrpc": "2.0", "id": 1, "result": []}', id="result-not-an-object"),
    pytest.param('{"jsonrpc": "2.0", "id": 1, "result": {}}', id="no-structured-content"),
    pytest.param('{"jsonrpc": "2.0", "id": 1, "error": {"code": 1}}', id="protocol-error"),
    pytest.param(None, id="dropped-connection"),
]


@pytest.mark.parametrize("body", MALFORMED_REPLIES)
def test_malformed_replies_raise_harness_error(stub: StubServer, body: str | None):
    stub.tools["probe"] = lambda arguments: body
    client = runner.McpClient(stub.url)
    client.initialize()
    with pytest.raises(runner.HarnessError):
        client.call("probe", {})


INITIALIZE_FAILURES = [
    pytest.param(
        '{"jsonrpc": "2.0", "id": 0, "error": {"code": 1}}', "initialize failed: {", id="error"
    ),
    pytest.param('{"jsonrpc": "2.0", "id": 0}', "has no result", id="no-result"),
    pytest.param("", "has no result", id="empty-body"),
    pytest.param("{not json", "not JSON", id="invalid-json"),
]


@pytest.mark.parametrize(("body", "message"), INITIALIZE_FAILURES)
def test_initialize_failures_are_harness_errors(stub: StubServer, body: str, message: str):
    stub.initialize_body = body
    with pytest.raises(runner.HarnessError, match=message):
        runner.McpClient(stub.url).initialize()


def test_event_stream_replies_are_decoded(stub: StubServer):
    stub.tools["probe"] = lambda arguments: f"event: message\ndata: {structured({'value': 7})}\n"
    client = runner.McpClient(stub.url)
    client.initialize()
    assert client.call("probe", {}).data == {"value": 7}


def test_call_timeout_is_a_harness_error(stub: StubServer, monkeypatch: pytest.MonkeyPatch):
    release = threading.Event()

    def slow(arguments: dict[str, Any]) -> str:
        release.wait(TOOL_REPLY_TIMEOUT_SECONDS)
        return structured({"value": 1})

    stub.tools["probe"] = slow
    monkeypatch.setattr(runner, "CALL_TIMEOUT_SECONDS", 0.2)
    client = runner.McpClient(stub.url)
    client.initialize()
    try:
        with pytest.raises(runner.HarnessError, match="cannot read from the MCP server"):
            client.call("probe", {})
    finally:
        release.set()


def test_wait_for_analysis_returns_once_completed(
    stub: StubServer, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(runner, "ANALYSIS_RETRY_SECONDS", 0.01)
    replies = iter([structured({"completed": False}), structured({"errorCode": "x"}, True)])
    stub.tools["rex_analysis_wait"] = lambda arguments: next(
        replies, structured({"completed": True})
    )
    client = runner.McpClient(stub.url)
    client.initialize()
    runner.wait_for_analysis(client, "h1")
    assert stub.call_names().count("rex_analysis_wait") == 3


def test_wait_for_analysis_gives_up_after_its_budget(
    stub: StubServer, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(runner, "ANALYSIS_BUDGET_SECONDS", 0.2)
    monkeypatch.setattr(runner, "ANALYSIS_RETRY_SECONDS", 0.01)
    stub.tools["rex_analysis_wait"] = lambda arguments: structured({"completed": False})
    client = runner.McpClient(stub.url)
    client.initialize()
    with pytest.raises(runner.HarnessError, match="did not finish"):
        runner.wait_for_analysis(client, "h1")
    assert stub.call_names().count("rex_analysis_wait") >= 2


def test_core_version_failure_is_a_harness_error(stub: StubServer):
    stub.tools["rex_eval_python"] = lambda arguments: structured({"error": "boom", "result": ""})
    client = runner.McpClient(stub.url)
    client.initialize()
    with pytest.raises(runner.HarnessError, match="could not read the Binary Ninja version"):
        runner.core_version(client, "h1")


def test_fixture_hash_mismatch_is_refused(tmp_path: Path, fixture_file: Path):
    playbook_path = write_playbook(tmp_path, fixture_file, [])
    fixture_file.write_bytes(b"changed")
    with pytest.raises(runner.HarnessError, match="pinned"):
        runner.run(playbook_path, "http://unused.invalid/mcp")


def test_unreachable_server_is_a_harness_error(
    stub: StubServer, tmp_path: Path, fixture_file: Path
):
    url = stub.url
    stub.shutdown()
    stub.server_close()
    playbook_path = write_playbook(tmp_path, fixture_file, [])
    with pytest.raises(runner.HarnessError, match="cannot read from the MCP server"):
        runner.run(playbook_path, url)


def test_run_passes_and_closes_the_opened_view(
    stub: StubServer, tmp_path: Path, fixture_file: Path, capsys: pytest.CaptureFixture[str]
):
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    assert runner.run(playbook_path, stub.url) == 0
    assert stub.calls[-1] == ("rex_binary_close", {"binary": "h1"})
    assert ("probe", {"binary": "h1"}) in stub.calls
    assert "1 passed, 0 failed of 1 steps" in capsys.readouterr().out


def test_run_warns_about_a_version_mismatch(
    stub: StubServer, tmp_path: Path, fixture_file: Path, capsys: pytest.CaptureFixture[str]
):
    playbook_path = write_playbook(tmp_path, fixture_file, [], version="2.0")
    assert runner.run(playbook_path, stub.url) == 0
    assert "WARNING: playbook pinned 2.0" in capsys.readouterr().out


def test_run_fails_when_a_step_fails(
    stub: StubServer, tmp_path: Path, fixture_file: Path, capsys: pytest.CaptureFixture[str]
):
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("bad", 2)])
    assert runner.run(playbook_path, stub.url) == 1
    assert "0 passed, 1 failed of 1 steps" in capsys.readouterr().out
    assert stub.call_names()[-1] == "rex_binary_close"


def test_run_does_not_close_when_the_open_fails(
    stub: StubServer, tmp_path: Path, fixture_file: Path
):
    stub.tools["bn_binary_open"] = lambda arguments: structured({"errorCode": "x"}, True)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    with pytest.raises(runner.HarnessError, match="bn_binary_open failed"):
        runner.run(playbook_path, stub.url)
    assert "rex_binary_close" not in stub.call_names()


def test_run_closes_the_view_when_analysis_never_finishes(
    stub: StubServer, tmp_path: Path, fixture_file: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(runner, "ANALYSIS_BUDGET_SECONDS", 0.1)
    monkeypatch.setattr(runner, "ANALYSIS_RETRY_SECONDS", 0.01)
    stub.tools["rex_analysis_wait"] = lambda arguments: structured({"completed": False})
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    with pytest.raises(runner.HarnessError, match="did not finish"):
        runner.run(playbook_path, stub.url)
    assert stub.call_names()[-1] == "rex_binary_close"


CLOSE_FAILURES = [
    pytest.param(lambda arguments: structured({"errorCode": "x"}, True), id="is-error"),
    pytest.param(lambda arguments: "", id="empty-body"),
    pytest.param(lambda arguments: "{not json", id="invalid-json"),
    pytest.param(lambda arguments: '{"jsonrpc": "2.0", "id": 1, "error": {"code": 1}}', id="rpc"),
    pytest.param(drop_connection, id="transport-error"),
]


@pytest.mark.parametrize("close_reply", CLOSE_FAILURES)
def test_close_failure_fails_the_run_without_hiding_the_summary(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    capsys: pytest.CaptureFixture[str],
    close_reply: ToolHandler,
):
    stub.tools["rex_binary_close"] = close_reply
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    assert runner.run(playbook_path, stub.url) == 1
    captured = capsys.readouterr()
    assert "1 passed, 0 failed of 1 steps" in captured.out
    assert "could not close the fixture view h1" in captured.err
    assert "still open" in captured.err


@pytest.mark.parametrize("close_reply", CLOSE_FAILURES)
def test_close_failure_does_not_make_step_counts_negative(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    capsys: pytest.CaptureFixture[str],
    close_reply: ToolHandler,
):
    stub.tools["rex_binary_close"] = close_reply
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("bad", 2)])
    assert runner.run(playbook_path, stub.url) == 1
    assert "0 passed, 1 failed of 1 steps" in capsys.readouterr().out


def test_main_exits_two_on_a_harness_error(
    tmp_path: Path, fixture_file: Path, monkeypatch: pytest.MonkeyPatch
):
    playbook_path = write_playbook(tmp_path, fixture_file, [])
    fixture_file.write_bytes(b"changed")
    monkeypatch.setattr(sys, "argv", ["run_playbook.py", "--playbook", str(playbook_path)])
    assert runner.main() == 2


HANDLED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def test_every_unwind_signal_is_handled():
    assert set(runner.UNWIND_SIGNALS) == set(HANDLED_SIGNALS)


def blocked_termination_signals() -> set[signal.Signals]:
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    return {number for number in runner.UNWIND_SIGNALS if number in blocked}


@pytest.mark.parametrize("termination_signal", HANDLED_SIGNALS)
def test_termination_during_the_open_stops_before_any_step_and_closes_the_view(
    stub: StubServer, tmp_path: Path, fixture_file: Path, termination_signal: signal.Signals
):
    open_started = threading.Event()
    release_open = threading.Event()

    def slow_open(arguments: dict[str, Any]) -> str:
        open_started.set()
        release_open.wait(TOOL_REPLY_TIMEOUT_SECONDS)
        return structured({"binary": {"handle": "h1"}})

    stub.tools["bn_binary_open"] = slow_open
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            str(RUNNER_PATH),
            "--url",
            stub.url,
            "--playbook",
            str(playbook_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert open_started.wait(TOOL_REPLY_TIMEOUT_SECONDS)
        process.send_signal(termination_signal)
        release_open.set()
        assert process.wait(TOOL_REPLY_TIMEOUT_SECONDS) == 128 + termination_signal
    finally:
        release_open.set()
        process.kill()
        process.wait()
    assert stub.call_names() == ["bn_binary_open", "rex_binary_close"]


@pytest.mark.parametrize("termination_signal", HANDLED_SIGNALS)
def test_termination_during_the_steps_stops_the_run_and_closes_the_view(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    termination_signal: signal.Signals,
):
    reached_after_signal: list[str] = []

    def interrupted_steps(playbook: dict[str, Any], binary: str, client: runner.McpClient) -> int:
        signal.raise_signal(termination_signal)
        reached_after_signal.append(binary)
        return 0

    monkeypatch.setattr(runner, "run_steps", interrupted_steps)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    with pytest.raises(SystemExit) as exit_info:
        runner.run(playbook_path, stub.url)
    assert exit_info.value.code == 128 + termination_signal
    assert reached_after_signal == []
    assert stub.call_names()[-1] == "rex_binary_close"


@pytest.mark.parametrize("termination_signal", HANDLED_SIGNALS)
def test_termination_arriving_at_the_close_request_waits_for_the_close(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    termination_signal: signal.Signals,
):
    close_fixture = runner.close_fixture

    def close_after_signal(client: runner.McpClient, binary: str) -> bool:
        signal.raise_signal(termination_signal)
        return close_fixture(client, binary)

    monkeypatch.setattr(runner, "close_fixture", close_after_signal)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    with pytest.raises(SystemExit) as exit_info:
        runner.run(playbook_path, stub.url)
    assert exit_info.value.code == 128 + termination_signal
    assert stub.call_names()[-1] == "rex_binary_close"


def test_termination_signals_are_blocked_during_the_close_request(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    close_fixture = runner.close_fixture
    blocked_during_close: list[set[signal.Signals]] = []

    def record_mask(client: runner.McpClient, binary: str) -> bool:
        blocked_during_close.append(blocked_termination_signals())
        return close_fixture(client, binary)

    monkeypatch.setattr(runner, "close_fixture", record_mask)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    assert runner.run(playbook_path, stub.url) == 0
    assert blocked_during_close == [set(runner.UNWIND_SIGNALS)]


def sentinel_handler(signal_number: int, frame: FrameType | None) -> None:
    raise AssertionError("the sentinel handler must never run")


def install_sentinel_state(blocked: signal.Signals) -> None:
    for number in runner.UNWIND_SIGNALS:
        signal.signal(number, sentinel_handler)
    signal.pthread_sigmask(signal.SIG_BLOCK, [blocked])


def signal_state() -> tuple[dict[signal.Signals, Any], set[int]]:
    handlers = {number: signal.getsignal(number) for number in runner.UNWIND_SIGNALS}
    return handlers, signal.pthread_sigmask(signal.SIG_BLOCK, [])


LEAK_SCENARIOS = [
    pytest.param(1, False, nullcontext(), id="pass"),
    pytest.param(2, False, nullcontext(), id="step-failure"),
    pytest.param(1, True, pytest.raises(runner.HarnessError), id="open-failure"),
]


@pytest.mark.parametrize(("expected_value", "open_fails", "outcome"), LEAK_SCENARIOS)
def test_run_leaves_the_signal_handlers_and_mask_as_it_found_them(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    expected_value: int,
    open_fails: bool,
    outcome: AbstractContextManager[object],
):
    if open_fails:
        stub.tools["bn_binary_open"] = lambda arguments: structured({"errorCode": "x"}, True)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("step", expected_value)])
    install_sentinel_state(signal.SIGHUP)
    before = signal_state()
    with outcome:
        runner.run(playbook_path, stub.url)
    assert signal_state() == before


@pytest.mark.parametrize("termination_signal", HANDLED_SIGNALS)
def test_termination_leaves_the_signal_handlers_and_mask_as_it_found_them(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    termination_signal: signal.Signals,
):
    close_fixture = runner.close_fixture

    def close_after_signal(client: runner.McpClient, binary: str) -> bool:
        signal.raise_signal(termination_signal)
        return close_fixture(client, binary)

    monkeypatch.setattr(runner, "close_fixture", close_after_signal)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    install_sentinel_state(signal.SIGUSR1)
    before = signal_state()
    with pytest.raises(SystemExit):
        runner.run(playbook_path, stub.url)
    assert signal_state() == before


@pytest.mark.parametrize("termination_signal", HANDLED_SIGNALS)
def test_termination_pending_from_the_open_still_closes_with_the_signals_blocked(
    stub: StubServer,
    tmp_path: Path,
    fixture_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    termination_signal: signal.Signals,
):
    open_fixture = runner.open_fixture
    close_fixture = runner.close_fixture
    blocked_during_close: list[set[signal.Signals]] = []

    def open_then_signal(client: runner.McpClient, fixture: Path) -> str:
        binary = open_fixture(client, fixture)
        signal.raise_signal(termination_signal)
        return binary

    def record_mask(client: runner.McpClient, binary: str) -> bool:
        blocked_during_close.append(blocked_termination_signals())
        return close_fixture(client, binary)

    monkeypatch.setattr(runner, "open_fixture", open_then_signal)
    monkeypatch.setattr(runner, "close_fixture", record_mask)
    playbook_path = write_playbook(tmp_path, fixture_file, [probe_step("good", 1)])
    with pytest.raises(SystemExit) as exit_info:
        runner.run(playbook_path, stub.url)
    assert exit_info.value.code == 128 + termination_signal
    assert blocked_during_close == [set(runner.UNWIND_SIGNALS)]
    assert stub.call_names() == ["bn_binary_open", "rex_binary_close"]


@pytest.mark.parametrize("termination_signal", HANDLED_SIGNALS)
def test_unwinding_ignores_every_further_termination_signal(termination_signal: signal.Signals):
    for number in runner.UNWIND_SIGNALS:
        signal.signal(number, runner.unwind_on_termination)
    with pytest.raises(SystemExit) as exit_info:
        runner.unwind_on_termination(termination_signal, None)
    assert exit_info.value.code == 128 + termination_signal
    for number in runner.UNWIND_SIGNALS:
        assert signal.getsignal(number) == signal.SIG_IGN
