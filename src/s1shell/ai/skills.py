"""Declarative defensive AI skills catalog loader (`skills.yaml` + `~/.s1shell/skills.d/`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from s1shell import __version__
from s1shell.errors import ValidationError
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class AISkill:
    """Single declarative defensive security analysis skill."""

    id: str
    name: str
    category: str
    description: str
    recommended_artifacts: list[str] = field(default_factory=list)
    output_sections: list[str] = field(default_factory=list)
    system_prompt: str = ""
    user_template: str = ""
    source: str = "bundled"


@dataclass(frozen=True)
class AISkillsCatalog:
    """Canonical artifact returned by `s1shell ai skills list`."""

    skills: list[AISkill]
    custom_count: int = 0
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ai_skills_catalog"


def _parse_skill_entry(raw: dict[str, Any], *, source: str) -> AISkill | None:
    sid = str(raw.get("id") or "").strip().lower()
    name = str(raw.get("name") or "").strip()
    sys_prompt = str(raw.get("system_prompt") or "").strip()
    if not sid or not name or not sys_prompt:
        return None
    return AISkill(
        id=sid,
        name=name,
        category=str(raw.get("category") or "general").strip().lower(),
        description=str(raw.get("description") or "").strip(),
        recommended_artifacts=[
            str(a).strip() for a in (raw.get("recommended_artifacts") or []) if str(a).strip()
        ],
        output_sections=[
            str(s).strip() for s in (raw.get("output_sections") or []) if str(s).strip()
        ],
        system_prompt=sys_prompt,
        user_template=str(raw.get("user_template") or "").strip(),
        source=source,
    )


def load_skills(*, extra_dir: Path | None = None) -> list[AISkill]:
    """Load bundled defensive AI skills plus optional custom `~/.s1shell/skills.d/*.yaml`."""
    raw_text = resources.files("s1shell.ai").joinpath("skills.yaml").read_text(encoding="utf-8")
    doc = yaml.safe_load(raw_text) or {}
    by_id: dict[str, AISkill] = {}

    if isinstance(doc, dict):
        for entry in doc.get("skills", []) or []:
            if isinstance(entry, dict):
                parsed = _parse_skill_entry(entry, source="bundled")
                if parsed is not None:
                    by_id[parsed.id] = parsed

    if extra_dir is not None and extra_dir.is_dir():
        for yaml_file in sorted(extra_dir.glob("*.y*ml")):
            try:
                extra_doc = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(extra_doc, dict):
                continue
            for entry in extra_doc.get("skills", []) or []:
                if isinstance(entry, dict):
                    parsed = _parse_skill_entry(entry, source=str(yaml_file))
                    if parsed is not None:
                        by_id[parsed.id] = parsed

    return list(by_id.values())


def get_skill(skill_id: str, *, extra_dir: Path | None = None) -> AISkill:
    """Resolve one skill by ID (case-insensitive) or raise ValidationError."""
    needle = skill_id.strip().lower()
    skills = load_skills(extra_dir=extra_dir)
    for skill in skills:
        if skill.id == needle:
            return skill
    available = ", ".join(s.id for s in skills)
    raise ValidationError(f"Unknown AI skill '{skill_id}'. Available skills: {available}.")


def build_skill_prompt_addendum(skill: AISkill) -> str:
    """Render structured system instructions for a chosen defensive AI skill."""
    parts = [
        f"Active defensive skill: {skill.name} (`{skill.id}`, category={skill.category}).",
        skill.system_prompt,
    ]
    if skill.output_sections:
        sec_list = ", ".join(f"({i}) {s}" for i, s in enumerate(skill.output_sections, start=1))
        parts.append(f"Structure your response into clear sections: {sec_list}.")
    return "\n\n".join(parts)
