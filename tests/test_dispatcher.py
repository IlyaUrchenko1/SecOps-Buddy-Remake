from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import Mock

from secopsbuddy.event_dispatcher import EventDispatcher, FileEventSink, LoggerEventSink


@dataclass
class CaptureSink:
    events: list[dict[str, Any]]

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def test_event_dispatcher_publishes_to_all_sinks() -> None:
    sink_a = CaptureSink(events=[])
    sink_b = CaptureSink(events=[])
    dispatcher = EventDispatcher([sink_a, sink_b])

    event = {"event": "detection_result", "status": "suspicious", "score": 0.9}
    dispatcher.publish(event)

    assert sink_a.events == [event]
    assert sink_b.events == [event]


def test_event_dispatcher_register_adds_sink() -> None:
    dispatcher = EventDispatcher([])
    sink = CaptureSink(events=[])

    dispatcher.register(sink)
    dispatcher.publish({"event": "test"})

    assert sink.events == [{"event": "test"}]


def test_logger_event_sink_serializes_event_to_json() -> None:
    logger = Mock()
    sink = LoggerEventSink(logger=logger)
    event = {"event": "detector_started", "detector_id": "t1030"}

    sink.emit(event)

    logger.info.assert_called_once()
    payload = logger.info.call_args.args[0]
    assert json.loads(payload) == event


def test_file_event_sink_writes_jsonl_lines(tmp_path: Path) -> None:
    output = tmp_path / "runtime" / "events.jsonl"
    sink = FileEventSink(file_path=str(output))

    first = {"event": "detector_started", "detector_id": "t1030"}
    second = {"event": "detection_result", "status": "clean"}

    sink.emit(first)
    sink.emit(second)

    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == first
    assert json.loads(lines[1]) == second
