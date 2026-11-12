"""Run the live playbook against the Binary Ninja MCP server."""

import argparse
import hashlib
import http.client
import json
import re
import signal
import sys
import time
import urllib.request
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any

HERE = Path(__file__).resolve().parent
DEFAULT_URL = "http://127.0.0.1:24642/mcp"
DEFAULT_PLAYBOOK = HERE / "playbook.json"
# The server runs handlers serially and cannot cancel them, so every call is bounded here.
CALL_TIMEOUT_SECONDS = 120
ANALYSIS_BUDGET_SECONDS = 120
ANALYSIS_RETRY_SECONDS = 1
UNWIND_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


class HarnessError(Exception):
    pass


@dataclass
class ToolResult:
    is_error: bool
    data: Any


@dataclass
class OpenedFixture:
    handle: str
    start: Any


def decode_reply(body: str) -> dict[str, Any]:
    if not body:
        return {}
    payload = body
    for line in body.splitlines():
        if line.startswith("data:"):
            payload = line[len("data:") :]
            break
    try:
        reply = json.loads(payload)
    except json.JSONDecodeError as error:
        raise HarnessError(f"the reply is not JSON: {body[:300]!r}") from error
    if not isinstance(reply, dict):
        raise HarnessError(f"the reply is not a JSON object: {body[:300]!r}")
    return reply


class McpClient:
    def __init__(self, url: str) -> None:
        self.url = url
        self.session_id: str | None = None
        self.next_id = 1

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id is not None:
            headers["Mcp-Session-Id"] = self.session_id
        request = urllib.request.Request(self.url, json.dumps(payload).encode(), headers)
        try:
            with urllib.request.urlopen(request, timeout=CALL_TIMEOUT_SECONDS) as response:
                self.session_id = response.headers.get("Mcp-Session-Id") or self.session_id
                body = response.read().decode().strip()
        except (OSError, http.client.HTTPException, UnicodeDecodeError) as error:
            raise HarnessError(f"cannot read from the MCP server at {self.url}: {error}") from error
        return decode_reply(body)

    def initialize(self) -> None:
        reply = self._post(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "run_playbook", "version": "1"},
                },
            }
        )
        if "error" in reply:
            raise HarnessError(f"initialize failed: {reply['error']}")
        if "result" not in reply:
            raise HarnessError(f"initialize failed: the reply has no result: {reply}")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool: str, arguments: dict[str, Any]) -> ToolResult:
        self.next_id += 1
        reply = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.next_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }
        )
        if "error" in reply:
            raise HarnessError(f"{tool}: protocol error {reply['error']}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise HarnessError(f"{tool}: the reply has no result: {reply}")
        data = result.get("structuredContent")
        if not isinstance(data, dict):
            raise HarnessError(f"{tool}: the reply has no structured content: {result}")
        return ToolResult(bool(result.get("isError")), data)


def text_of(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def at_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split(".") if path else []:
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(f"path '{path}' is missing at '{part}'")
    return current


def dict_mismatch(expected: dict[str, Any], actual: Any, where: str) -> str | None:
    if not isinstance(actual, dict):
        return f"{where}: expected an object, got {actual!r}"
    for key, value in expected.items():
        if key not in actual:
            return f"{where}.{key}: missing"
        reason = subset_mismatch(value, actual[key], f"{where}.{key}")
        if reason is not None:
            return reason
    return None


def list_mismatch(expected: list[Any], actual: Any, where: str) -> str | None:
    if not isinstance(actual, list) or len(actual) != len(expected):
        return f"{where}: expected a list of {len(expected)}, got {actual!r}"
    for index, value in enumerate(expected):
        reason = subset_mismatch(value, actual[index], f"{where}[{index}]")
        if reason is not None:
            return reason
    return None


def subset_mismatch(expected: Any, actual: Any, where: str = "$") -> str | None:
    if isinstance(expected, dict):
        return dict_mismatch(expected, actual, where)
    if isinstance(expected, list):
        return list_mismatch(expected, actual, where)
    if expected != actual or type(expected) is not type(actual):
        return f"{where}: expected {expected!r}, got {actual!r}"
    return None


def check_subset(assertion: dict[str, Any], value: Any) -> str | None:
    return subset_mismatch(assertion["value"], value)


def check_contains(assertion: dict[str, Any], value: Any) -> str | None:
    if assertion["text"] in text_of(value):
        return None
    return f"expected text {assertion['text']!r} not found in {text_of(value)[:300]!r}"


def check_not_contains(assertion: dict[str, Any], value: Any) -> str | None:
    if assertion["text"] not in text_of(value):
        return None
    return f"forbidden text {assertion['text']!r} found in {text_of(value)[:300]!r}"


def check_regex(assertion: dict[str, Any], value: Any) -> str | None:
    if not isinstance(value, str):
        return f"expected a string for regex {assertion['pattern']!r}, got {value!r}"
    if re.search(assertion["pattern"], value):
        return None
    return f"regex {assertion['pattern']!r} did not match {value[:300]!r}"


def check_not_regex(assertion: dict[str, Any], value: Any) -> str | None:
    if not re.search(assertion["pattern"], text_of(value)):
        return None
    return f"forbidden regex {assertion['pattern']!r} matched {text_of(value)[:300]!r}"


def matching_items(assertion: dict[str, Any], value: Any) -> list[int]:
    if not isinstance(value, list):
        raise KeyError(f"expected a list, got {value!r}")
    return [
        index
        for index, item in enumerate(value)
        if subset_mismatch(assertion["item"], item) is None
    ]


def check_includes(assertion: dict[str, Any], value: Any) -> str | None:
    if matching_items(assertion, value):
        return None
    return f"no element matches {assertion['item']!r} in {text_of(value)[:300]!r}"


def check_excludes(assertion: dict[str, Any], value: Any) -> str | None:
    matches = matching_items(assertion, value)
    if not matches:
        return None
    return f"forbidden element {assertion['item']!r} found at index {matches[0]}"


def check_length(assertion: dict[str, Any], value: Any) -> str | None:
    if isinstance(value, list) and len(value) == assertion["value"]:
        return None
    return f"expected a list of {assertion['value']}, got {text_of(value)[:300]!r}"


def check_unique(assertion: dict[str, Any], value: Any) -> str | None:
    if not isinstance(value, list):
        return f"expected a list, got {value!r}"
    seen: set[str] = set()
    for item in value:
        key = text_of(item)
        if key in seen:
            return f"duplicate element {key[:300]}"
        seen.add(key)
    return None


def check_sorted_hex(assertion: dict[str, Any], value: Any) -> str | None:
    if not isinstance(value, list):
        return f"expected a list, got {value!r}"
    numbers = [int(item, 16) for item in value]
    if numbers == sorted(numbers):
        return None
    return f"not ascending: {value}"


VALUE_CHECKS = {
    "subset": check_subset,
    "contains": check_contains,
    "not_contains": check_not_contains,
    "regex": check_regex,
    "not_regex": check_not_regex,
    "includes": check_includes,
    "excludes": check_excludes,
    "length": check_length,
    "unique": check_unique,
    "sorted_hex": check_sorted_hex,
}


def check_error_code(assertion: dict[str, Any], result: ToolResult) -> str | None:
    if not result.is_error:
        return f"expected error {assertion['code']!r}, got success {text_of(result.data)[:300]!r}"
    code = result.data.get("errorCode")
    if code != assertion["code"]:
        return f"expected error code {assertion['code']!r}, got {code!r}: {result.data}"
    needle = assertion.get("message_contains")
    message = result.data.get("errorMessage", "")
    if needle and needle not in message:
        return f"error message lacks {needle!r}: {message!r}"
    forbidden = assertion.get("message_lacks")
    if forbidden and forbidden in message:
        return f"error message has forbidden text {forbidden!r}: {message!r}"
    return None


def parity_view(result: ToolResult, path: str, fields: list[str]) -> dict[str, Any]:
    data = at_path(result.data, path)
    return {field: at_path(data, field) for field in fields}


def check_parity(assertion: dict[str, Any], result: ToolResult, client: McpClient) -> str | None:
    other = assertion["against"]
    other_result = client.call(other["tool"], other["args"])
    if result.is_error != other_result.is_error:
        return (
            f"{other['tool']} error={other_result.is_error} differs from "
            f"error={result.is_error}: {other_result.data} vs {result.data}"
        )
    expect_error = assertion.get("expect_error", False)
    if result.is_error != expect_error:
        outcome = "both returned errors" if result.is_error else "both succeeded"
        return f"{outcome}, but the step expects {'errors' if expect_error else 'success'}"
    left = parity_view(result, assertion.get("path", ""), assertion["fields"])
    right = parity_view(other_result, "", assertion["fields"])
    if left == right:
        return None
    return f"differs from {other['tool']}: {text_of(left)[:300]} vs {text_of(right)[:300]}"


def run_value_check(assertion: dict[str, Any], result: ToolResult) -> str | None:
    kind = assertion["kind"]
    if kind not in VALUE_CHECKS:
        return f"unknown expect kind {kind!r}"
    if result.is_error:
        return f"tool returned an error: {text_of(result.data)[:300]}"
    value = at_path(result.data, assertion.get("path", ""))
    return VALUE_CHECKS[kind](assertion, value)


def run_assertion(assertion: dict[str, Any], result: ToolResult, client: McpClient) -> str | None:
    kind = assertion["kind"]
    try:
        if kind == "error_code":
            return check_error_code(assertion, result)
        if kind == "parity":
            return check_parity(assertion, result, client)
        return run_value_check(assertion, result)
    except (KeyError, TypeError, ValueError) as error:
        return f"{type(error).__name__}: {error}"


def run_step(step: dict[str, Any], binary: str, client: McpClient) -> list[str]:
    arguments = {"binary": binary, **step["args"]}
    result = client.call(step["tool"], arguments)
    failures = []
    for assertion in step["expect"]:
        reason = run_assertion(with_binary(assertion, binary), result, client)
        if reason is not None:
            failures.append(f"{assertion['kind']}: {reason}")
    return failures


def with_binary(assertion: dict[str, Any], binary: str) -> dict[str, Any]:
    if assertion["kind"] != "parity":
        return assertion
    against = assertion["against"]
    return {**assertion, "against": {**against, "args": {"binary": binary, **against["args"]}}}


def verify_fixture(playbook: dict[str, Any]) -> Path:
    fixture = (HERE / Path(playbook["fixture"]["path"])).resolve()
    actual = hashlib.sha256(fixture.read_bytes()).hexdigest()
    if actual != playbook["fixture"]["sha256"]:
        raise HarnessError(
            f"{fixture} sha256 {actual} != pinned {playbook['fixture']['sha256']}; "
            "rebuild with build.sh and re-pin, or restore the committed binary"
        )
    return fixture


def open_fixture(client: McpClient, fixture: Path) -> OpenedFixture:
    result = client.call("bn_binary_open", {"path": str(fixture)})
    if result.is_error:
        raise HarnessError(f"bn_binary_open failed: {result.data}")
    binary = result.data["binary"]
    return OpenedFixture(str(binary["handle"]), binary.get("start"))


def fixture_base(playbook: dict[str, Any]) -> int:
    base = playbook["fixture"].get("base")
    try:
        return int(base, 16)
    except (TypeError, ValueError) as error:
        raise HarnessError(f"the playbook fixture base is not a hex address: {base!r}") from error


def check_fixture_base(opened: OpenedFixture, expected: int) -> None:
    try:
        actual = int(opened.start, 16)
    except (TypeError, ValueError) as error:
        raise HarnessError(f"the view start is not a hex address: {opened.start!r}") from error
    if actual != expected:
        raise HarnessError(f"fixture loaded at {actual:#x}, expected {expected:#x}")


def wait_for_analysis(client: McpClient, binary: str) -> None:
    deadline = time.monotonic() + ANALYSIS_BUDGET_SECONDS
    while time.monotonic() < deadline:
        result = client.call("rex_analysis_wait", {"binary": binary, "timeout_ms": 10000})
        if not result.is_error and result.data["completed"]:
            return
        time.sleep(ANALYSIS_RETRY_SECONDS)
    raise HarnessError(f"analysis did not finish within {ANALYSIS_BUDGET_SECONDS} seconds")


def core_version(client: McpClient, binary: str) -> str:
    result = client.call(
        "rex_eval_python", {"binary": binary, "code": "result = binaryninja.core_version()"}
    )
    if result.is_error or result.data["error"]:
        raise HarnessError(f"could not read the Binary Ninja version: {result.data}")
    return str(result.data["result"]).strip("'\"")


def run_steps(playbook: dict[str, Any], binary: str, client: McpClient) -> int:
    failed = 0
    for step in playbook["steps"]:
        try:
            failures = run_step(step, binary, client)
        except HarnessError as error:
            failures = [f"HarnessError: {error}"]
        except Exception as error:
            failures = [f"unexpected {type(error).__name__}: {error}"]
        if failures:
            failed += 1
            print(f"FAIL {step['id']}")
            print(f"       guards: {step['guards']}")
            for failure in failures:
                print(f"       {failure}")
            continue
        print(f"PASS {step['id']}")
    return failed


def close_fixture(client: McpClient, binary: str) -> bool:
    try:
        closed = client.call("rex_binary_close", {"binary": binary})
    except HarnessError as error:
        print(f"ERROR: could not close the fixture view {binary}: {error}", file=sys.stderr)
        return False
    if closed.is_error:
        print(f"ERROR: could not close the fixture view {binary}: {closed.data}", file=sys.stderr)
        return False
    return True


def unwind_on_termination(signal_number: int, frame: FrameType | None) -> None:
    for ignored in UNWIND_SIGNALS:
        signal.signal(ignored, signal.SIG_IGN)
    raise SystemExit(128 + signal_number)


@contextmanager
def unwind_signals_unblocked() -> Generator[None]:
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, UNWIND_SIGNALS)
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, UNWIND_SIGNALS)


@contextmanager
def unwind_handlers_installed() -> Generator[None]:
    previous_handlers = {number: signal.getsignal(number) for number in UNWIND_SIGNALS}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, UNWIND_SIGNALS)
    try:
        for number in UNWIND_SIGNALS:
            signal.signal(number, unwind_on_termination)
        yield
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        finally:
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)


def run_opened(
    playbook: dict[str, Any], client: McpClient, opened: OpenedFixture, base: int
) -> int:
    binary = opened.handle
    failed = 0
    try:
        with unwind_signals_unblocked():
            check_fixture_base(opened, base)
            wait_for_analysis(client, binary)
            version = core_version(client, binary)
            print(f"Binary Ninja {version}; fixture {binary}")
            if version != playbook["binary_ninja_version"]:
                print(f"WARNING: playbook pinned {playbook['binary_ninja_version']}")
            failed = run_steps(playbook, binary, client)
    finally:
        closed = close_fixture(client, binary)
    total = len(playbook["steps"])
    print(f"{total - failed} passed, {failed} failed of {total} steps")
    if not closed:
        print(f"ERROR: the fixture view {binary} is still open; close it by hand", file=sys.stderr)
    return 1 if failed or not closed else 0


def run(playbook_path: Path, url: str) -> int:
    playbook = json.loads(playbook_path.read_text())
    fixture = verify_fixture(playbook)
    base = fixture_base(playbook)
    client = McpClient(url)
    client.initialize()
    with unwind_handlers_installed():
        opened = open_fixture(client, fixture)
        return run_opened(playbook, client, opened, base)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--playbook", type=Path, default=DEFAULT_PLAYBOOK)
    arguments = parser.parse_args()
    try:
        return run(arguments.playbook, arguments.url)
    except HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
