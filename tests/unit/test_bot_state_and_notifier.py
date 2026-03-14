from __future__ import annotations

from secopsbuddy.bot.notifier import render_event
from secopsbuddy.bot.state import BotRuntimeState


def test_bot_runtime_state_tracks_alerts_and_mute_flags() -> None:
    state = BotRuntimeState()

    for idx in range(35):
        state.add_alert(f"alert-{idx}")

    text = state.recent_alerts_text()

    assert "1. alert-34" in text
    assert len(state.recent_alerts) == 30

    assert state.toggle_mute(1001) is True
    assert state.is_muted(1001) is True
    assert state.toggle_mute(1001) is False
    assert state.is_muted(1001) is False


def test_render_event_returns_none_for_clean_detection() -> None:
    event = {
        "event": "detection_result",
        "mitre_id": "T1030",
        "status": "clean",
        "score": 0.1,
    }

    assert render_event(event) is None


def test_render_event_formats_suspicious_alert_with_keyboard() -> None:
    event = {
        "event": "detection_result",
        "mitre_id": "T1030",
        "status": "suspicious",
        "score": 0.95,
        "findings_count": 1,
        "summary": "summary <danger>",
        "timestamp": "2026-03-14T00:00:00Z",
        "findings": [
            {
                "remote_ip": "93.184.216.34",
                "remote_port": 443,
                "process_name": "python",
                "score": 0.95,
            }
        ],
    }

    rendered = render_event(event)

    assert rendered is not None
    text, keyboard, category = rendered
    assert category == "alert"
    assert "93.184.216.34" in text
    assert "&lt;danger&gt;" in text
    assert keyboard is not None


def test_render_event_filters_successful_firewall_actions() -> None:
    blocked_event = {
        "event": "firewall_action",
        "mitre_id": "T1030",
        "blocked": True,
        "ip": "8.8.8.8",
    }
    failed_event = {
        "event": "firewall_action",
        "mitre_id": "T1030",
        "blocked": False,
        "ip": "8.8.8.8",
        "message": "failed",
    }

    assert render_event(blocked_event) is None

    rendered = render_event(failed_event)
    assert rendered is not None
    text, _keyboard, category = rendered
    assert category == "action"
    assert "8.8.8.8" in text
