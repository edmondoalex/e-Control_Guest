from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Command:
    domain: str
    service: str
    entity_id: str
    data: dict[str, Any]


ACTION_CATALOG = {
    "light": {
        "turn_on": ("turn_on", None, None),
        "turn_off": ("turn_off", None, None),
        "set_brightness": ("turn_on", "brightness", (0, 255)),
    },
    "switch": {
        "turn_on": ("turn_on", None, None),
        "turn_off": ("turn_off", None, None),
    },
    "climate": {
        "set_temperature": ("set_temperature", "temperature", (5, 35)),
        "set_hvac_mode": ("set_hvac_mode", "hvac_mode", None),
    },
    "cover": {
        "open": ("open_cover", None, None),
        "close": ("close_cover", None, None),
        "stop": ("stop_cover", None, None),
        "set_position": ("set_cover_position", "position", (0, 100)),
    },
    "button": {"press": ("press", None, None)},
}


class PolicyDenied(PermissionError):
    pass


def suggested_actions(entity_id: str) -> list[str]:
    domain = entity_id.partition(".")[0]
    return list(ACTION_CATALOG.get(domain, {}))


SAFE_ATTRIBUTES = {
    "light": {"friendly_name", "icon", "brightness", "color_temp_kelvin", "supported_color_modes"},
    "switch": {"friendly_name", "icon", "device_class"},
    "climate": {"friendly_name", "icon", "temperature", "current_temperature", "hvac_action",
                "hvac_modes", "min_temp", "max_temp", "target_temp_step", "unit_of_measurement"},
    "cover": {"friendly_name", "icon", "device_class", "current_position"},
    "button": {"friendly_name", "icon", "device_class"},
}


def public_state(value: dict) -> dict:
    entity_id = str(value.get("entity_id") or "")
    domain = entity_id.partition(".")[0]
    attributes = value.get("attributes") if isinstance(value.get("attributes"), dict) else {}
    allowed = SAFE_ATTRIBUTES.get(domain, {"friendly_name", "icon", "unit_of_measurement", "device_class"})
    return {
        "entity_id": entity_id,
        "state": str(value.get("state") or "unknown")[:100],
        "attributes": {key: attributes[key] for key in allowed if key in attributes
                       and isinstance(attributes[key], (str, int, float, bool, list, type(None)))},
    }


def authorize(permissions: dict, entity_id: str, action: str, value: Any = None) -> Command:
    if not isinstance(permissions, dict) or entity_id not in permissions:
        raise PolicyDenied("entity_not_shared")
    policy = permissions[entity_id]
    if not isinstance(policy, dict) or action not in policy.get("actions", []):
        raise PolicyDenied("action_not_allowed")
    domain, separator, object_id = entity_id.partition(".")
    if separator != "." or not object_id or domain not in ACTION_CATALOG or action not in ACTION_CATALOG[domain]:
        raise PolicyDenied("unsupported_action")
    service, value_field, absolute_limits = ACTION_CATALOG[domain][action]
    data: dict[str, Any] = {"entity_id": entity_id}
    if value_field:
        if value is None:
            raise PolicyDenied("value_required")
        limits = policy.get("limits", {}).get(value_field)
        limits = limits if isinstance(limits, list) and len(limits) == 2 else absolute_limits
        if absolute_limits:
            try:
                numeric = float(value)
            except (TypeError, ValueError) as exc:
                raise PolicyDenied("invalid_value") from exc
            low = max(float(absolute_limits[0]), float(limits[0])) if limits else float(absolute_limits[0])
            high = min(float(absolute_limits[1]), float(limits[1])) if limits else float(absolute_limits[1])
            if numeric < low or numeric > high:
                raise PolicyDenied("value_out_of_range")
            value = int(numeric) if numeric.is_integer() else numeric
        elif not isinstance(value, str) or not value or len(value) > 32:
            raise PolicyDenied("invalid_value")
        elif value_field == "hvac_mode":
            allowed = policy.get("limits", {}).get("allowed_values", [])
            if not isinstance(allowed, list) or value not in allowed:
                raise PolicyDenied("value_not_allowed")
        data[value_field] = value
    return Command(domain=domain, service=service, entity_id=entity_id, data=data)
