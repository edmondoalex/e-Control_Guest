from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterator

from .policy import suggested_actions


SAFE_CARD_TYPES = {"entities", "entity", "tile", "thermostat", "button", "gauge", "sensor"}
CONTAINER_CARD_TYPES = {"vertical-stack", "horizontal-stack", "grid"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entity_rows(card: dict) -> list[dict]:
    rows: list[dict] = []

    def add(value: Any) -> None:
        if isinstance(value, str):
            entity_id, name, icon = value, "", ""
        elif isinstance(value, dict):
            entity_id = value.get("entity")
            name, icon = value.get("name", ""), value.get("icon", "")
        else:
            return
        if isinstance(entity_id, str) and "." in entity_id and entity_id not in {item["entity_id"] for item in rows}:
            rows.append({
                "entity_id": entity_id,
                "name": str(name or "")[:100],
                "icon": str(icon or "")[:100],
                "suggested_actions": suggested_actions(entity_id),
            })

    add(card.get("entity"))
    for item in card.get("entities", []) if isinstance(card.get("entities"), list) else []:
        add(item)
    return rows


@dataclass(frozen=True)
class CardCandidate:
    source_ref: str
    dashboard: str
    view_title: str
    title: str
    card_type: str
    safe: bool
    reason: str
    source_hash: str
    config: dict
    entities: list[dict]

    def public(self) -> dict:
        return {
            "source_ref": self.source_ref,
            "dashboard": self.dashboard,
            "view_title": self.view_title,
            "title": self.title,
            "card_type": self.card_type,
            "safe": self.safe,
            "reason": self.reason,
            "source_hash": self.source_hash,
            "entities": self.entities,
        }


def _walk_cards(cards: list, prefix: str) -> Iterator[tuple[str, dict]]:
    for index, card in enumerate(cards):
        if not isinstance(card, dict):
            continue
        path = f"{prefix}.cards[{index}]"
        yield path, card
        if card.get("type") in CONTAINER_CARD_TYPES and isinstance(card.get("cards"), list):
            yield from _walk_cards(card["cards"], path)


def inspect_dashboard(config: dict, dashboard: str = "lovelace") -> list[CardCandidate]:
    if not isinstance(config, dict) or not isinstance(config.get("views"), list):
        if isinstance(config, dict) and isinstance(config.get("strategy"), dict):
            raise ValueError("Dashboard generata automaticamente: non contiene schede importabili")
        raise ValueError("Configurazione dashboard non valida o priva di schede importabili")
    candidates: list[CardCandidate] = []
    for view_index, view in enumerate(config["views"]):
        if not isinstance(view, dict):
            continue
        view_title = str(view.get("title") or view.get("path") or f"Vista {view_index + 1}")[:100]
        groups: list[tuple[str, list]] = []
        if isinstance(view.get("cards"), list):
            groups.append((f"views[{view_index}]", view["cards"]))
        if isinstance(view.get("sections"), list):
            for section_index, section in enumerate(view["sections"]):
                if isinstance(section, dict) and isinstance(section.get("cards"), list):
                    groups.append((f"views[{view_index}].sections[{section_index}]", section["cards"]))
        for prefix, cards in groups:
            for source_ref, card in _walk_cards(cards, prefix):
                card_type = str(card.get("type") or "unknown")
                custom = card_type.startswith("custom:")
                safe = card_type in SAFE_CARD_TYPES and not custom
                entities = _entity_rows(card)
                reason = "" if safe else ("custom_card_not_executable" if custom else "card_type_not_supported")
                candidates.append(CardCandidate(
                    source_ref=source_ref,
                    dashboard=dashboard,
                    view_title=view_title,
                    title=str(card.get("title") or card.get("name") or view_title)[:100],
                    card_type=card_type,
                    safe=safe,
                    reason=reason,
                    source_hash=hashlib.sha256(_canonical(card)).hexdigest(),
                    config=card,
                    entities=entities,
                ))
    return candidates


def snapshot(candidate: CardCandidate) -> dict:
    if not candidate.safe:
        raise ValueError(candidate.reason or "Card non supportata")
    return {
        "source_ref": candidate.source_ref,
        "source_hash": candidate.source_hash,
        "title": candidate.title,
        "type": candidate.card_type,
        "entities": [
            {"entity_id": item["entity_id"], "name": item["name"], "icon": item["icon"]}
            for item in candidate.entities
        ],
        "permissions": {
            item["entity_id"]: {"read": True, "actions": [], "limits": {}}
            for item in candidate.entities
        },
    }
