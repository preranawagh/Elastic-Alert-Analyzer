"""Shared ECS field helpers used across enrichment / investigation / reports."""

import ipaddress


def get_field(doc, *paths):
    """
    Read a field using either dotted ECS keys or nested dicts.
    Also supports a single nested walk when the top-level key exists.
    """
    if not isinstance(doc, dict):
        return None

    for path in paths:
        if not path:
            continue

        if "." not in path:
            value = doc.get(path)
            if value is not None:
                return value
            continue

        # Flat dotted key (common in Elastic Security alerts)
        if path in doc and doc[path] is not None:
            return doc[path]

        # Nested dict walk
        current = doc
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current is not None:
            return current

    return None


def as_text(value):
    """Normalize ECS values that may be str, list, or other types."""
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [str(v) for v in value if v is not None and v != ""]
        return " ".join(parts)
    return str(value)


def as_lower(value):
    return as_text(value).lower()


def first_value(*values):
    """Return the first non-empty value."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        return value
    return None


def flatten_values(value):
    """Flatten a scalar or list into a list of unique non-empty strings."""
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = [value]

    result = []
    seen = set()
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def is_private_ip(ip):
    """Return True for private / loopback / link-local / unspecified IPs."""
    if not ip:
        return True
    try:
        obj = ipaddress.ip_address(str(ip).strip())
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_unspecified
            or obj.is_multicast
            or obj.is_reserved
        )
    except ValueError:
        return True


def pick_public_ip(*candidates):
    """Return the first public IP from candidates (scalars or lists)."""
    for candidate in candidates:
        for ip in flatten_values(candidate):
            if not is_private_ip(ip):
                return ip
    return None
