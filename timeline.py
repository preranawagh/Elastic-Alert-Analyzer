from datetime import datetime

from ecs_utils import as_text, as_lower


def _parse_ts(value):
    if not value:
        return None
    text = str(value)
    try:
        # Support Z suffix
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _add_event(events, timestamp, category, action, detail, source="investigation"):
    events.append({
        "timestamp": timestamp,
        "category": as_text(category) or "other",
        "action": as_text(action) or "event",
        "detail": as_text(detail),
        "source": source,
    })


def build_timeline(alert, investigation, max_events=100):
    """
    Build a chronological incident timeline from the alert
    and investigation evidence.
    """
    events = []
    inv = investigation or {}

    alert_ts = (
        alert.get("@timestamp")
        if isinstance(alert, dict)
        else None
    )
    rule = (
        alert.get("kibana.alert.rule.name")
        if isinstance(alert, dict)
        else None
    )
    process = None
    host = None
    if isinstance(alert, dict):
        process = (
            alert.get("process.name")
            or (alert.get("process") or {}).get("name")
        )
        host = (
            alert.get("host.name")
            or (alert.get("host") or {}).get("name")
        )

    _add_event(
        events,
        alert_ts,
        "alert",
        "triggered",
        f"Alert '{rule}' on host {host} process={process}",
        source="alert",
    )

    parent = inv.get("parent_process") or {}
    if parent and parent.get("name"):
        _add_event(
            events,
            parent.get("timestamp") or alert_ts,
            "process",
            "parent",
            (
                f"Parent {parent.get('name')} "
                f"pid={parent.get('pid')} "
                f"cmd={parent.get('command_line') or parent.get('name')}"
            ),
        )

    for child in inv.get("child_processes") or []:
        if isinstance(child, dict) and child.get("_error"):
            continue
        _add_event(
            events,
            child.get("timestamp"),
            "process",
            "child_created",
            (
                f"Child {child.get('name')} "
                f"pid={child.get('pid')} "
                f"cmd={child.get('command_line')}"
            ),
        )

    for item in inv.get("file_creations") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "file",
            "created",
            (
                f"File created {item.get('path')} "
                f"by={item.get('process')}"
            ),
        )

    for item in inv.get("file_modifications") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "file",
            "modified",
            (
                f"File modified {item.get('path')} "
                f"by={item.get('process')}"
            ),
        )

    for item in inv.get("registry_changes") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        path = item.get("path") or item.get("key")
        _add_event(
            events,
            item.get("timestamp"),
            "registry",
            item.get("action") or "change",
            (
                f"Registry {path} "
                f"value={item.get('value')} "
                f"by={item.get('process')}"
            ),
        )

    for item in inv.get("network_connections") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "network",
            "connection",
            (
                f"{item.get('process')} "
                f"{item.get('source_ip')}:{item.get('source_port')} -> "
                f"{item.get('destination_ip')}:"
                f"{item.get('destination_port')}"
            ),
        )

    for item in inv.get("dns_events") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "dns",
            "query",
            (
                f"DNS {item.get('question')} -> "
                f"{item.get('resolved_ip')} "
                f"by={item.get('process')}"
            ),
        )

    for item in inv.get("authentication_events") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "authentication",
            item.get("action") or "auth",
            (
                f"User {item.get('user')} "
                f"outcome={item.get('outcome')} "
                f"from={item.get('source_ip')}"
            ),
        )

    for item in inv.get("services") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "service",
            item.get("action") or "service",
            (
                f"Service {item.get('name')} "
                f"path={item.get('path')}"
            ),
        )

    for item in inv.get("scheduled_tasks") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            "scheduled_task",
            item.get("action") or "task",
            (
                f"Task {item.get('task_name')} "
                f"cmd={item.get('command')}"
            ),
        )

    persistence = inv.get("persistence") or {}
    for item in persistence.get("registry_persistence") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        path = item.get("path") or item.get("key")
        _add_event(
            events,
            item.get("timestamp"),
            "persistence",
            "registry",
            f"Persistence registry path {path}",
        )

    for item in inv.get("related_events") or []:
        if isinstance(item, dict) and item.get("_error"):
            continue
        _add_event(
            events,
            item.get("timestamp"),
            item.get("category") or "related",
            item.get("action") or "event",
            (
                f"Related process={item.get('process')} "
                f"message={item.get('message')}"
            ),
            source="related",
        )

    def sort_key(event):
        parsed = _parse_ts(event.get("timestamp"))
        category = as_lower(event.get("category")).split()[0] if as_text(
            event.get("category")
        ) else "other"
        # Prefer primary category token when ECS sends multi-value lists
        category_rank = {
            "alert": 0,
            "process": 1,
            "file": 2,
            "registry": 3,
            "network": 4,
            "dns": 5,
            "authentication": 6,
            "service": 7,
            "scheduled_task": 8,
            "persistence": 9,
        }.get(category, 50)
        # Primary: time, secondary: category order
        return (
            parsed or datetime.max,
            category_rank,
            as_text(event.get("action")),
        )

    events.sort(key=sort_key)
    trimmed = events[:max_events]

    return {
        "event_count": len(trimmed),
        "events": trimmed,
    }


def print_timeline(timeline, limit=15):
    print("\nIncident Timeline")
    print("-" * 60)

    events = (timeline or {}).get("events") or []
    if not events:
        print("  No timeline events")
        return

    print(f"Events        : {(timeline or {}).get('event_count', 0)}")
    for event in events[:limit]:
        ts = event.get("timestamp") or "unknown-time"
        print(
            f"  [{ts}] "
            f"{event.get('category')}/{event.get('action')} "
            f"- {event.get('detail')}"
        )

    remaining = len(events) - limit
    if remaining > 0:
        print(f"  ... and {remaining} more")
