from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol


class EventSink(Protocol):
    def emit(self, event: dict[str, Any]) -> None:
        ...


@dataclass(slots=True)
class EventDispatcher:
    sinks: list[EventSink] = field(default_factory=list)

    def register(self, sink: EventSink) -> None:
        self.sinks.append(sink)

    def publish(self, event: dict[str, Any]) -> None:
        for sink in self.sinks:
            sink.emit(event)


@dataclass(slots=True)
class LoggerEventSink:
    logger: Any

    def emit(self, event: dict[str, Any]) -> None:
        self.logger.info(json.dumps(event, ensure_ascii=False))
