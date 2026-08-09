from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

from budobugs.labs.manager import LabManager


def test_native_fixture_tracks_and_reaps_the_exact_process_tree(repository_root: Path, tmp_path: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    manager = LabManager(repository_root, tmp_path / "runtime", fixture_port=port)
    state: dict[str, object] | None = None
    primary_error: BaseException | None = None
    try:
        status = manager.up(native_only=True)
        assert status.running
        state = json.loads(manager.state_file.read_text(encoding="utf-8"))
        assert state["schema_version"] == 2
        required_tokens = manager._native_required_tokens(state)
        owned = manager._matching_process_ids(required_tokens)
        assert state["pid"] in owned
        assert set(state["owned_pids"]) == owned
        snapshot = manager._process_snapshot()
        assert all(all(token.lower() in snapshot[pid][1] for token in required_tokens) for pid in owned)
        if sys.platform == "win32":
            listeners = manager._listener_process_ids(port)
            assert listeners
            assert listeners <= owned
        else:
            assert manager._http_health(port, "/healthz")

        stopped = manager.down()
        assert not stopped.running
        assert stopped.backend == "none"
        assert stopped.services == {"fixture": False}
        assert not manager.state_file.exists()
        assert not manager._matching_process_ids(required_tokens)
        assert not manager._http_health(port, "/healthz", timeout=0.25)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if manager.state_file.exists():
            try:
                manager.down()
            except BaseException as cleanup_error:
                if primary_error is None:
                    raise
                primary_error.add_note(f"native fixture cleanup also failed: {cleanup_error!r}")
