from datetime import datetime, timedelta, timezone

from dateutil import parser as date_parser

from elastic_client import es
from config import (
    LOGS_INDEX,
    INVESTIGATION_WINDOW_MINUTES,
    INVESTIGATION_SIZE,
)
from ecs_utils import get_field, as_text, as_lower, first_value


# ======================================================
# Helpers
# ======================================================

def _get_field(doc, *paths):
    """Compatibility wrapper around shared ECS getter."""
    return get_field(doc, *paths)


def _parse_timestamp(value):
    if not value:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    try:
        parsed = date_parser.isoparse(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError):
        return None


def _time_range(timestamp, window_minutes=None):
    """
    Build a ± window around the alert timestamp.
    Returns (start_iso, end_iso) or (None, None).
    """
    if window_minutes is None:
        window_minutes = INVESTIGATION_WINDOW_MINUTES

    ts = _parse_timestamp(timestamp)
    if not ts:
        return None, None

    delta = timedelta(minutes=window_minutes)
    start = (ts - delta).isoformat()
    end = (ts + delta).isoformat()
    return start, end


def _base_filters(host=None, start=None, end=None):
    """Common host + time filters for investigation queries."""
    filters = []

    if start and end:
        filters.append({
            "range": {
                "@timestamp": {
                    "gte": start,
                    "lte": end
                }
            }
        })

    if host:
        filters.append({
            "bool": {
                "should": [
                    {"term": {"host.name": host}},
                    {"term": {"host.name.keyword": host}},
                ],
                "minimum_should_match": 1
            }
        })

    return filters


def _search(must=None, filters=None, size=None):
    """Run a search against the configured logs index."""
    if size is None:
        size = INVESTIGATION_SIZE

    query = {
        "bool": {
            "must": must or [],
            "filter": filters or []
        }
    }

    try:
        response = es.search(
            index=LOGS_INDEX,
            size=size,
            sort=[{"@timestamp": {"order": "asc"}}],
            query=query,
            ignore_unavailable=True
        )
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as exc:
        return [{"_error": str(exc)}]


def _summarize_process(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "name": _get_field(event, "process.name"),
        "pid": _get_field(event, "process.pid"),
        "entity_id": _get_field(event, "process.entity_id"),
        "executable": _get_field(event, "process.executable"),
        "command_line": _get_field(event, "process.command_line"),
        "user": _get_field(event, "user.name"),
        "parent_name": _get_field(event, "process.parent.name"),
        "parent_pid": _get_field(event, "process.parent.pid"),
        "parent_entity_id": _get_field(
            event, "process.parent.entity_id"
        ),
        "parent_command_line": _get_field(
            event, "process.parent.command_line"
        ),
        "hash_sha256": _get_field(event, "process.hash.sha256"),
        "action": as_text(_get_field(event, "event.action")),
    }


def _summarize_file(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "action": as_text(_get_field(event, "event.action")),
        "type": _get_field(event, "event.type"),
        "path": _get_field(event, "file.path"),
        "name": _get_field(event, "file.name"),
        "directory": _get_field(event, "file.directory"),
        "extension": _get_field(event, "file.extension"),
        "hash_sha256": _get_field(event, "file.hash.sha256"),
        "hash_md5": _get_field(event, "file.hash.md5"),
        "process": _get_field(event, "process.name"),
        "process_pid": _get_field(event, "process.pid"),
        "user": _get_field(event, "user.name"),
    }


def _summarize_registry(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "action": as_text(_get_field(event, "event.action")),
        "hive": _get_field(event, "registry.hive"),
        "key": _get_field(event, "registry.key"),
        "path": _get_field(event, "registry.path"),
        "value": _get_field(event, "registry.value"),
        "data": (
            _get_field(event, "registry.data.strings")
            or _get_field(event, "registry.data.bytes")
        ),
        "process": _get_field(event, "process.name"),
        "process_pid": _get_field(event, "process.pid"),
        "user": _get_field(event, "user.name"),
    }


def _summarize_network(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "action": as_text(_get_field(event, "event.action")),
        "source_ip": _get_field(event, "source.ip"),
        "source_port": _get_field(event, "source.port"),
        "destination_ip": _get_field(event, "destination.ip"),
        "destination_port": _get_field(event, "destination.port"),
        "protocol": _get_field(
            event, "network.protocol", "network.transport"
        ),
        "direction": _get_field(event, "network.direction"),
        "process": _get_field(event, "process.name"),
        "process_pid": _get_field(event, "process.pid"),
        "user": _get_field(event, "user.name"),
    }


def _summarize_dns(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "question": _get_field(event, "dns.question.name"),
        "type": _get_field(event, "dns.question.type"),
        "resolved_ip": (
            _get_field(event, "dns.resolved_ip")
            or _get_field(event, "dns.answers.data")
        ),
        "response_code": _get_field(event, "dns.response_code"),
        "process": _get_field(event, "process.name"),
        "user": _get_field(event, "user.name"),
    }


def _summarize_auth(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "action": as_text(_get_field(event, "event.action")),
        "outcome": as_text(_get_field(event, "event.outcome")),
        "user": _get_field(event, "user.name"),
        "source_ip": _get_field(event, "source.ip"),
        "destination_ip": _get_field(event, "destination.ip"),
        "logon_type": _get_field(
            event, "winlog.event_data.LogonType"
        ),
        "host": _get_field(event, "host.name"),
    }


def _summarize_service(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "action": as_text(_get_field(event, "event.action")),
        "name": (
            _get_field(event, "service.name")
            or _get_field(event, "winlog.event_data.ServiceName")
        ),
        "path": (
            _get_field(event, "service.path")
            or _get_field(
                event, "winlog.event_data.ImagePath"
            )
        ),
        "start_type": _get_field(
            event, "winlog.event_data.StartType"
        ),
        "user": (
            _get_field(event, "user.name")
            or _get_field(
                event, "winlog.event_data.AccountName"
            )
        ),
        "process": _get_field(event, "process.name"),
    }


def _summarize_scheduled_task(event):
    return {
        "timestamp": _get_field(event, "@timestamp"),
        "action": as_text(_get_field(event, "event.action")),
        "task_name": (
            _get_field(event, "winlog.event_data.TaskName")
            or _get_field(event, "process.name")
        ),
        "command": (
            _get_field(event, "process.command_line")
            or _get_field(
                event, "winlog.event_data.TaskContent"
            )
        ),
        "user": _get_field(event, "user.name"),
        "host": _get_field(event, "host.name"),
    }


def extract_alert_context(alert):
    """Pull investigation pivots from an Elastic Security alert."""
    return {
        "timestamp": _get_field(alert, "@timestamp"),
        "host": _get_field(alert, "host.name"),
        "user": _get_field(alert, "user.name"),
        "process_name": _get_field(alert, "process.name"),
        "process_pid": _get_field(alert, "process.pid"),
        "process_entity_id": _get_field(
            alert, "process.entity_id"
        ),
        "process_executable": _get_field(
            alert, "process.executable"
        ),
        "process_command_line": _get_field(
            alert, "process.command_line"
        ),
        "parent_name": _get_field(
            alert, "process.parent.name"
        ),
        "parent_pid": _get_field(
            alert, "process.parent.pid"
        ),
        "parent_entity_id": _get_field(
            alert, "process.parent.entity_id"
        ),
        "file_name": _get_field(alert, "file.name"),
        "file_path": _get_field(alert, "file.path"),
        "file_hash": first_value(
            _get_field(alert, "file.hash.sha256"),
            _get_field(alert, "process.hash.sha256"),
            _get_field(alert, "file.hash.sha1"),
            _get_field(alert, "file.hash.md5"),
            _get_field(alert, "process.hash.md5"),
        ),
    }


# ======================================================
# Process Investigation
# ======================================================

def investigate_process(alert, window_minutes=None):
    """
    Gather parent process, child processes, and a simple
    process tree around the alerted process.
    """
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    parent = None
    children = []
    process_events = []

    # Prefer entity_id when available (Elastic Defend)
    entity_id = ctx["process_entity_id"]
    pid = ctx["process_pid"]
    parent_entity_id = ctx["parent_entity_id"]

    # Parent: use alert fields first, then query if needed
    if ctx["parent_name"] or parent_entity_id:
        parent = {
            "name": ctx["parent_name"],
            "pid": ctx["parent_pid"],
            "entity_id": parent_entity_id,
            "source": "alert",
        }

    if parent_entity_id:
        parent_hits = _search(
            must=[{
                "bool": {
                    "should": [
                        {"term": {
                            "process.entity_id": parent_entity_id
                        }},
                        {"term": {
                            "process.entity_id.keyword":
                                parent_entity_id
                        }},
                    ],
                    "minimum_should_match": 1
                }
            }],
            filters=filters + [{
                "term": {"event.category": "process"}
            }],
            size=5
        )
        if parent_hits and "_error" not in parent_hits[0]:
            parent = _summarize_process(parent_hits[0])
            parent["source"] = "elasticsearch"

    # Child processes: events where parent is the alert process
    child_must = [{"term": {"event.category": "process"}}]

    if entity_id:
        child_must.append({
            "bool": {
                "should": [
                    {"term": {
                        "process.parent.entity_id": entity_id
                    }},
                    {"term": {
                        "process.parent.entity_id.keyword":
                            entity_id
                    }},
                ],
                "minimum_should_match": 1
            }
        })
    elif pid is not None:
        child_must.append({
            "term": {"process.parent.pid": pid}
        })
    else:
        child_must = None

    if child_must:
        child_hits = _search(
            must=child_must,
            filters=filters,
            size=INVESTIGATION_SIZE
        )
        if child_hits and "_error" not in child_hits[0]:
            children = [
                _summarize_process(e) for e in child_hits
            ]
        elif child_hits and "_error" in child_hits[0]:
            children = child_hits

    # Related process activity for the same process
    process_must = [{"term": {"event.category": "process"}}]

    if entity_id:
        process_must.append({
            "bool": {
                "should": [
                    {"term": {"process.entity_id": entity_id}},
                    {"term": {
                        "process.entity_id.keyword": entity_id
                    }},
                ],
                "minimum_should_match": 1
            }
        })
    elif pid is not None:
        process_must.append({"term": {"process.pid": pid}})
    elif ctx["process_name"]:
        process_must.append({
            "term": {"process.name": ctx["process_name"]}
        })
    else:
        process_must = None

    if process_must:
        process_hits = _search(
            must=process_must,
            filters=filters
        )
        if process_hits and "_error" not in process_hits[0]:
            process_events = [
                _summarize_process(e) for e in process_hits
            ]
        elif process_hits and "_error" in process_hits[0]:
            process_events = process_hits

    # Simple tree: parent -> alert process -> children
    tree_base = {
        "parent": parent,
        "process": {
            "name": ctx["process_name"],
            "pid": ctx["process_pid"],
            "entity_id": entity_id,
            "executable": ctx["process_executable"],
            "command_line": ctx["process_command_line"],
            "user": ctx["user"],
        },
        "children": children,
    }
    tree = {
        **tree_base,
        "display": format_process_tree_text(tree_base, ascii_mode=False),
        "display_ascii": format_process_tree_text(
            tree_base, ascii_mode=True
        ),
    }

    return {
        "parent_process": parent,
        "child_processes": children,
        "process_tree": tree,
        "process_events": process_events,
    }


def format_process_tree_text(tree, ascii_mode=False):
    """
    Render a readable process tree.

    Unicode (HTML):
      explorer.exe
      └── Code.exe
          └── powershell.exe

    ASCII (PDF-safe):
      explorer.exe (pid=1234)
        |
        +--> Code.exe (pid=5678)
               |
               +--> powershell.exe (pid=9012)
    """
    tree = tree or {}
    parent = tree.get("parent") or {}
    process = tree.get("process") or {}
    children = tree.get("children") or []

    def label(node):
        if not node:
            return "unknown"
        name = node.get("name") or "unknown"
        pid = node.get("pid")
        return f"{name} (pid={pid})" if pid is not None else name

    lines = []
    if parent and parent.get("name"):
        lines.append(label(parent))
        if ascii_mode:
            lines.append("  |")
            lines.append(f"  +--> {label(process)}")
            child_stem = "         |"
            child_branch = "         +--> "
        else:
            lines.append(f"└── {label(process)}")
            child_stem = None
            child_branch = "    "
    else:
        lines.append(label(process))
        if ascii_mode:
            child_stem = "  |"
            child_branch = "  +--> "
        else:
            child_stem = None
            child_branch = ""

    valid_children = [
        c for c in children
        if isinstance(c, dict) and not c.get("_error")
    ]
    for index, child in enumerate(valid_children[:10]):
        if ascii_mode:
            lines.append(child_stem)
            lines.append(f"{child_branch}{label(child)}")
        else:
            prefix = child_branch
            connector = (
                "└──"
                if index == len(valid_children[:10]) - 1
                else "├──"
            )
            lines.append(f"{prefix}{connector} {label(child)}")

    return "\n".join(lines) if lines else "No process tree data"


# ======================================================
# File Investigation
# ======================================================

def investigate_files(alert, window_minutes=None):
    """File creations and modifications on the alert host."""
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    must = [
        {"term": {"event.category": "file"}},
    ]

    # Optionally scope to the alert process
    process_filter = []
    if ctx["process_entity_id"]:
        process_filter.append({
            "bool": {
                "should": [
                    {"term": {
                        "process.entity_id":
                            ctx["process_entity_id"]
                    }},
                    {"term": {
                        "process.entity_id.keyword":
                            ctx["process_entity_id"]
                    }},
                ],
                "minimum_should_match": 1
            }
        })
    elif ctx["process_pid"] is not None:
        process_filter.append({
            "term": {"process.pid": ctx["process_pid"]}
        })

    hits = _search(must=must, filters=filters)

    if hits and "_error" in hits[0]:
        return {
            "file_creations": hits,
            "file_modifications": hits,
            "all_file_events": hits,
        }

    creations = []
    modifications = []
    all_events = []

    for event in hits:
        summary = _summarize_file(event)
        all_events.append(summary)

        action = as_lower(summary.get("action"))
        event_types = summary.get("type") or []
        if isinstance(event_types, str):
            event_types = [event_types]
        event_types = [as_lower(t) for t in event_types]

        if (
            "creation" in action
            or "create" in action
            or "creation" in event_types
        ):
            creations.append(summary)
        elif (
            "modification" in action
            or "change" in action
            or "overwrite" in action
            or "change" in event_types
            or "modification" in event_types
        ):
            modifications.append(summary)

    # Also query process-scoped file events if we have a pivot
    process_scoped = []
    if process_filter:
        scoped_hits = _search(
            must=must + process_filter,
            filters=filters
        )
        if scoped_hits and "_error" not in scoped_hits[0]:
            process_scoped = [
                _summarize_file(e) for e in scoped_hits
            ]

    return {
        "file_creations": creations,
        "file_modifications": modifications,
        "process_file_events": process_scoped,
        "all_file_events": all_events,
    }


# ======================================================
# Registry Investigation
# ======================================================

def investigate_registry(alert, window_minutes=None):
    """Windows registry changes around the alert."""
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    # Prefer process-scoped registry, also collect host-wide
    process_must = [{"term": {"event.category": "registry"}}]
    if ctx["process_entity_id"]:
        process_must.append({
            "bool": {
                "should": [
                    {"term": {
                        "process.entity_id":
                            ctx["process_entity_id"]
                    }},
                    {"term": {
                        "process.entity_id.keyword":
                            ctx["process_entity_id"]
                    }},
                ],
                "minimum_should_match": 1
            }
        })
    elif ctx["process_pid"] is not None:
        process_must.append({
            "term": {"process.pid": ctx["process_pid"]}
        })

    process_hits = _search(must=process_must, filters=filters)
    host_hits = _search(
        must=[{"term": {"event.category": "registry"}}],
        filters=filters
    )

    def _safe_summarize(hits):
        if not hits:
            return []
        if "_error" in hits[0]:
            return hits
        return [_summarize_registry(e) for e in hits]

    process_events = _safe_summarize(process_hits)
    host_events = _safe_summarize(host_hits)

    # Persistence-oriented registry paths
    persistence_keywords = [
        "\\run",
        "\\runonce",
        "\\services\\",
        "winlogon",
        "currentversion\\explorer\\shell",
        "image file execution options",
        "appinit_dlls",
        "startupapproved",
    ]

    persistence = []
    for event in (
        process_events
        if process_events and "_error" not in str(process_events[0])
        else host_events
    ):
        if isinstance(event, dict) and event.get("_error"):
            continue
        path = (
            str(event.get("path") or "")
            + str(event.get("key") or "")
        ).lower()
        if any(k in path for k in persistence_keywords):
            persistence.append(event)

    return {
        "process_registry_events": process_events,
        "host_registry_events": host_events,
        "persistence_registry": persistence,
    }


# ======================================================
# Network Investigation
# ======================================================

def investigate_network(alert, window_minutes=None):
    """Network connections and DNS around the alert."""
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    network_must = [{"term": {"event.category": "network"}}]
    dns_must = [
        {
            "bool": {
                "should": [
                    {"term": {"event.category": "network"}},
                    {"exists": {"field": "dns.question.name"}},
                ],
                "minimum_should_match": 1
            }
        },
        {"exists": {"field": "dns.question.name"}},
    ]

    if ctx["process_entity_id"]:
        entity_clause = {
            "bool": {
                "should": [
                    {"term": {
                        "process.entity_id":
                            ctx["process_entity_id"]
                    }},
                    {"term": {
                        "process.entity_id.keyword":
                            ctx["process_entity_id"]
                    }},
                ],
                "minimum_should_match": 1
            }
        }
        network_must.append(entity_clause)
        dns_must.append(entity_clause)
    elif ctx["process_pid"] is not None:
        network_must.append({
            "term": {"process.pid": ctx["process_pid"]}
        })

    network_hits = _search(must=network_must, filters=filters)
    # Host-wide DNS in the window (often not process-linked)
    dns_hits = _search(
        must=[
            {"exists": {"field": "dns.question.name"}},
        ],
        filters=filters
    )

    def _safe(hits, summarizer):
        if not hits:
            return []
        if "_error" in hits[0]:
            return hits
        return [summarizer(e) for e in hits]

    return {
        "network_connections": _safe(
            network_hits, _summarize_network
        ),
        "dns_events": _safe(dns_hits, _summarize_dns),
    }


# ======================================================
# Auth / Logon Investigation
# ======================================================

def investigate_authentication(alert, window_minutes=None):
    """Authentication and user logon events on the host."""
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    must = [
        {
            "bool": {
                "should": [
                    {"term": {
                        "event.category": "authentication"
                    }},
                    {"term": {"event.category": "session"}},
                    # Common Windows logon event IDs
                    {"terms": {
                        "event.code": [
                            "4624", "4625", "4648",
                            "4672", "4768", "4769", "4776"
                        ]
                    }},
                ],
                "minimum_should_match": 1
            }
        }
    ]

    hits = _search(must=must, filters=filters)

    if not hits:
        return {"authentication_events": [], "user_logons": []}

    if "_error" in hits[0]:
        return {
            "authentication_events": hits,
            "user_logons": hits,
        }

    events = [_summarize_auth(e) for e in hits]
    logons = [
        e for e in events
        if as_lower(e.get("action")) in (
            "logged-in", "logon", "log-on", "success"
        )
        or as_lower(e.get("outcome")) == "success"
    ]

    return {
        "authentication_events": events,
        "user_logons": logons or events,
    }


# ======================================================
# Services & Scheduled Tasks
# ======================================================

def investigate_services(alert, window_minutes=None):
    """Service creation / modification events."""
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    must = [
        {
            "bool": {
                "should": [
                    {"term": {"event.category": "service"}},
                    {"term": {"event.code": "7045"}},
                    {"wildcard": {
                        "event.action": "*service*"
                    }},
                ],
                "minimum_should_match": 1
            }
        }
    ]

    hits = _search(must=must, filters=filters)

    if not hits:
        return {"services": []}
    if "_error" in hits[0]:
        return {"services": hits}

    return {
        "services": [_summarize_service(e) for e in hits]
    }


def investigate_scheduled_tasks(alert, window_minutes=None):
    """Scheduled task creation / modification events."""
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    must = [
        {
            "bool": {
                "should": [
                    {"wildcard": {
                        "event.action": "*scheduled_task*"
                    }},
                    {"wildcard": {
                        "event.action": "*schedule*"
                    }},
                    {"terms": {
                        "event.code": [
                            "4698", "4699", "4700",
                            "4701", "4702"
                        ]
                    }},
                    {"match_phrase": {
                        "message": "scheduled task"
                    }},
                ],
                "minimum_should_match": 1
            }
        }
    ]

    hits = _search(must=must, filters=filters)

    if not hits:
        return {"scheduled_tasks": []}
    if "_error" in hits[0]:
        return {"scheduled_tasks": hits}

    return {
        "scheduled_tasks": [
            _summarize_scheduled_task(e) for e in hits
        ]
    }


# ======================================================
# Persistence Mechanisms
# ======================================================

def investigate_persistence(alert, window_minutes=None):
    """
    Aggregate common persistence signals:
    registry Run keys, services, scheduled tasks,
    startup folder drops, and WMI-like events.
    """
    registry = investigate_registry(alert, window_minutes)
    services = investigate_services(alert, window_minutes)
    tasks = investigate_scheduled_tasks(alert, window_minutes)
    files = investigate_files(alert, window_minutes)

    startup_folder = []
    for item in (files.get("file_creations") or []) + (
        files.get("file_modifications") or []
    ):
        if not isinstance(item, dict) or item.get("_error"):
            continue
        path = as_lower(item.get("path") or item.get("name"))
        if any(
            marker in path
            for marker in (
                "\\startup\\",
                "/startup/",
                "start menu\\programs\\startup",
                "start menu/programs/startup",
            )
        ):
            startup_folder.append(item)

    wmi_persistence = []
    for item in (files.get("all_file_events") or []) + (
        registry.get("host_registry_events") or []
    ):
        if not isinstance(item, dict) or item.get("_error"):
            continue
        blob = as_lower(
            str(item.get("path") or "")
            + str(item.get("key") or "")
            + str(item.get("name") or "")
            + str(item.get("action") or "")
        )
        if any(
            marker in blob
            for marker in (
                "wmi",
                "__eventfilter",
                "commandlineseventconsumer",
                "permanent event consumer",
            )
        ):
            wmi_persistence.append(item)

    return {
        "registry_persistence": registry.get(
            "persistence_registry", []
        ),
        "services": services.get("services", []),
        "scheduled_tasks": tasks.get("scheduled_tasks", []),
        "startup_folder": startup_folder,
        "wmi_persistence": wmi_persistence,
    }


# ======================================================
# Related Events
# ======================================================

def investigate_related_events(alert, window_minutes=None):
    """
    Broad related activity on the same host within the
    configurable time window (± minutes around alert).
    """
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)
    filters = _base_filters(ctx["host"], start, end)

    must = [
        {
            "terms": {
                "event.category": [
                    "process",
                    "file",
                    "registry",
                    "network",
                    "authentication",
                    "session",
                    "service",
                ]
            }
        }
    ]

    hits = _search(
        must=must,
        filters=filters,
        size=INVESTIGATION_SIZE
    )

    if not hits:
        return {"related_events": [], "window": {
            "start": start,
            "end": end,
            "minutes": window_minutes or INVESTIGATION_WINDOW_MINUTES,
        }}

    if "_error" in hits[0]:
        return {
            "related_events": hits,
            "window": {
                "start": start,
                "end": end,
                "minutes": (
                    window_minutes or INVESTIGATION_WINDOW_MINUTES
                ),
            },
        }

    related = []
    for event in hits:
        related.append({
            "timestamp": _get_field(event, "@timestamp"),
            "category": _get_field(event, "event.category"),
            "action": as_text(_get_field(event, "event.action")),
            "type": _get_field(event, "event.type"),
            "process": _get_field(event, "process.name"),
            "user": _get_field(event, "user.name"),
            "message": _get_field(event, "message"),
            "file_path": _get_field(event, "file.path"),
            "destination_ip": _get_field(
                event, "destination.ip"
            ),
        })

    return {
        "related_events": related,
        "window": {
            "start": start,
            "end": end,
            "minutes": window_minutes or INVESTIGATION_WINDOW_MINUTES,
        },
    }


# ======================================================
# Master Function
# ======================================================

def investigate_alert(alert, window_minutes=None):
    """
    Run a full host/process investigation for one alert.
    Does NOT call external TI APIs — Elasticsearch only.
    """
    ctx = extract_alert_context(alert)
    start, end = _time_range(ctx["timestamp"], window_minutes)

    def _safe(label, fn):
        try:
            return fn()
        except Exception as exc:
            return {"_error": f"{label}: {exc}"}

    process = _safe(
        "process",
        lambda: investigate_process(alert, window_minutes),
    )
    files = _safe(
        "files",
        lambda: investigate_files(alert, window_minutes),
    )
    registry = _safe(
        "registry",
        lambda: investigate_registry(alert, window_minutes),
    )
    network = _safe(
        "network",
        lambda: investigate_network(alert, window_minutes),
    )
    auth = _safe(
        "authentication",
        lambda: investigate_authentication(
            alert, window_minutes
        ),
    )
    services = _safe(
        "services",
        lambda: investigate_services(alert, window_minutes),
    )
    tasks = _safe(
        "scheduled_tasks",
        lambda: investigate_scheduled_tasks(
            alert, window_minutes
        ),
    )
    related = _safe(
        "related_events",
        lambda: investigate_related_events(
            alert, window_minutes
        ),
    )

    # Normalize failed sections so callers always get lists
    if "_error" in process:
        process = {
            "parent_process": None,
            "child_processes": [{"_error": process["_error"]}],
            "process_tree": None,
            "process_events": [],
        }
    if "_error" in files:
        files = {
            "file_creations": [{"_error": files["_error"]}],
            "file_modifications": [],
            "process_file_events": [],
            "all_file_events": [],
        }
    if "_error" in registry:
        registry = {
            "process_registry_events": [],
            "host_registry_events": [
                {"_error": registry["_error"]}
            ],
            "persistence_registry": [],
        }
    if "_error" in network:
        network = {
            "network_connections": [
                {"_error": network["_error"]}
            ],
            "dns_events": [],
        }
    if "_error" in auth:
        auth = {
            "authentication_events": [
                {"_error": auth["_error"]}
            ],
            "user_logons": [],
        }
    if "_error" in services:
        services = {
            "services": [{"_error": services["_error"]}]
        }
    if "_error" in tasks:
        tasks = {
            "scheduled_tasks": [{"_error": tasks["_error"]}]
        }
    if "_error" in related:
        related = {
            "related_events": [
                {"_error": related["_error"]}
            ],
            "window": {
                "start": start,
                "end": end,
                "minutes": (
                    window_minutes
                    or INVESTIGATION_WINDOW_MINUTES
                ),
            },
        }

    persistence = {
        "registry_persistence": registry.get(
            "persistence_registry", []
        ),
        "services": services.get("services", []),
        "scheduled_tasks": tasks.get("scheduled_tasks", []),
        "startup_folder": [],
        "wmi_persistence": [],
    }

    for item in (files.get("file_creations") or []) + (
        files.get("file_modifications") or []
    ):
        if not isinstance(item, dict) or item.get("_error"):
            continue
        path = as_lower(item.get("path") or item.get("name"))
        if any(
            marker in path
            for marker in (
                "\\startup\\",
                "/startup/",
                "start menu\\programs\\startup",
                "start menu/programs/startup",
            )
        ):
            persistence["startup_folder"].append(item)

    for item in (files.get("all_file_events") or []) + (
        registry.get("host_registry_events") or []
    ):
        if not isinstance(item, dict) or item.get("_error"):
            continue
        blob = as_lower(
            str(item.get("path") or "")
            + str(item.get("key") or "")
            + str(item.get("name") or "")
            + str(item.get("action") or "")
        )
        if any(
            marker in blob
            for marker in (
                "wmi",
                "__eventfilter",
                "commandlineseventconsumer",
                "permanent event consumer",
            )
        ):
            persistence["wmi_persistence"].append(item)

    return {
        "context": ctx,
        "window": {
            "start": start,
            "end": end,
            "minutes": window_minutes or INVESTIGATION_WINDOW_MINUTES,
            "index": LOGS_INDEX,
        },
        "parent_process": process.get("parent_process"),
        "child_processes": process.get("child_processes", []),
        "process_tree": process.get("process_tree"),
        "file_creations": files.get("file_creations", []),
        "file_modifications": files.get("file_modifications", []),
        "registry_changes": registry.get(
            "host_registry_events", []
        ),
        "network_connections": network.get(
            "network_connections", []
        ),
        "dns_events": network.get("dns_events", []),
        "authentication_events": auth.get(
            "authentication_events", []
        ),
        "user_logons": auth.get("user_logons", []),
        "services": services.get("services", []),
        "scheduled_tasks": tasks.get("scheduled_tasks", []),
        "persistence": persistence,
        "related_events": related.get("related_events", []),
    }


def print_investigation(result):
    """Pretty-print investigation results (for CLI use)."""

    def _count(items):
        if not items:
            return 0
        if isinstance(items, list) and items and isinstance(
            items[0], dict
        ) and "_error" in items[0]:
            return f"error: {items[0]['_error']}"
        return len(items)

    def _print_items(title, items, formatter, limit=5):
        print(f"\n{title} ({_count(items)})")
        if not items:
            print("  No data")
            return
        if isinstance(items[0], dict) and "_error" in items[0]:
            print(f"  Error: {items[0]['_error']}")
            return
        for item in items[:limit]:
            print(f"  - {formatter(item)}")
        if len(items) > limit:
            print(f"  ... and {len(items) - limit} more")

    print("\nInvestigation")
    print("-" * 60)

    window = result.get("window") or {}
    ctx = result.get("context") or {}

    print(
        f"Window        : ±{window.get('minutes')} min "
        f"({window.get('start')} → {window.get('end')})"
    )
    print(f"Index         : {window.get('index')}")
    print(
        f"Alert Process : {ctx.get('process_name')} "
        f"(pid={ctx.get('process_pid')}, "
        f"entity_id={ctx.get('process_entity_id')})"
    )
    print(f"Alert User    : {ctx.get('user')}")
    print(f"Alert Host    : {ctx.get('host')}")

    parent = result.get("parent_process")
    if parent:
        print(
            f"Parent Process: {parent.get('name')} "
            f"(pid={parent.get('pid')}, "
            f"entity_id={parent.get('entity_id')})"
        )
    else:
        print("Parent Process: No data")

    _print_items(
        "Child Processes",
        result.get("child_processes"),
        lambda c: (
            f"{c.get('name')} pid={c.get('pid')} "
            f"cmd={c.get('command_line')}"
        ),
    )
    _print_items(
        "File Creations",
        result.get("file_creations"),
        lambda f: (
            f"{f.get('action')} path={f.get('path')} "
            f"by={f.get('process')}"
        ),
    )
    _print_items(
        "File Modifications",
        result.get("file_modifications"),
        lambda f: (
            f"{f.get('action')} path={f.get('path')} "
            f"by={f.get('process')}"
        ),
    )
    _print_items(
        "Registry Changes",
        result.get("registry_changes"),
        lambda r: (
            f"{r.get('action')} path={r.get('path') or r.get('key')} "
            f"by={r.get('process')}"
        ),
    )
    _print_items(
        "Network Connections",
        result.get("network_connections"),
        lambda n: (
            f"{n.get('process')} "
            f"{n.get('source_ip')}:{n.get('source_port')} -> "
            f"{n.get('destination_ip')}:{n.get('destination_port')}"
        ),
    )
    _print_items(
        "DNS Events",
        result.get("dns_events"),
        lambda d: (
            f"{d.get('question')} -> {d.get('resolved_ip')} "
            f"by={d.get('process')}"
        ),
    )
    _print_items(
        "Auth / Logons",
        result.get("authentication_events"),
        lambda a: (
            f"{a.get('user')} action={a.get('action')} "
            f"outcome={a.get('outcome')} "
            f"from={a.get('source_ip')}"
        ),
    )
    _print_items(
        "Services",
        result.get("services"),
        lambda s: (
            f"{s.get('name')} path={s.get('path')} "
            f"action={s.get('action')}"
        ),
    )
    _print_items(
        "Scheduled Tasks",
        result.get("scheduled_tasks"),
        lambda t: (
            f"{t.get('task_name')} cmd={t.get('command')}"
        ),
    )

    persistence = result.get("persistence") or {}
    print(
        f"\nPersistence    : "
        f"registry={_count(persistence.get('registry_persistence'))} | "
        f"services={_count(persistence.get('services'))} | "
        f"tasks={_count(persistence.get('scheduled_tasks'))} | "
        f"startup={_count(persistence.get('startup_folder'))} | "
        f"wmi={_count(persistence.get('wmi_persistence'))}"
    )

    tree = (result.get("process_tree") or {}).get("display")
    if tree:
        print("\nProcess Tree")
        for line in str(tree).splitlines():
            print(f"  {line}")

    _print_items(
        "Related Events",
        result.get("related_events"),
        lambda e: (
            f"{e.get('timestamp')} "
            f"[{e.get('category')}/{e.get('action')}] "
            f"process={e.get('process')}"
        ),
    )
