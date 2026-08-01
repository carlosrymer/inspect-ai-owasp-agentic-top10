"""The Inspect task: one support-desk suite, parameterised by defensive posture."""

from __future__ import annotations

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.agent import as_solver
from inspect_ai.dataset import MemoryDataset, Sample

from .agent import seed_environment, support_agent
from .scenarios import (
    OWASP_CLASSES,
    PAYLOADS,
    SCENARIOS,
    build_environment,
    instruction_for,
)
from .scorers import attack_success, task_utility
from .tools import POSTURES

COMPOSE = (Path(__file__).parent / "compose.yaml").as_posix()


def _clean_sample(scenario_id: str) -> Sample:
    sc = SCENARIOS[scenario_id]
    return Sample(
        id=f"{sc.id}::clean",
        input=instruction_for(sc),
        metadata={
            "files": build_environment(sc, None),
            "utility": sc.utility,
            "attack": [],
            "attacked": False,
            "asi": "none",
            "asi_name": "No attack",
            "payload_id": "",
            "payload_channel": "",
            "payload_note": "",
            "scenario": sc.id,
            "scenario_title": sc.title,
            "scenario_summary": sc.summary,
            "canary": sc.canary,
        },
    )


def _attack_sample(payload_id: str) -> Sample:
    payload = next(p for p in PAYLOADS if p.id == payload_id)
    sc = SCENARIOS[payload.scenario]
    return Sample(
        id=f"{sc.id}::{payload.id}",
        input=instruction_for(sc),
        metadata={
            "files": build_environment(sc, payload),
            "utility": sc.utility,
            "attack": payload.success_if_any,
            "attacked": True,
            "asi": payload.asi,
            "asi_name": OWASP_CLASSES[payload.asi],
            "payload_id": payload.id,
            "payload_channel": payload.channel,
            "payload_note": payload.note,
            "payload_text": payload.text,
            "scenario": sc.id,
            "scenario_title": sc.title,
            "scenario_summary": sc.summary,
            "canary": sc.canary,
        },
    )


def build_dataset(subset: str = "all") -> MemoryDataset:
    samples: list[Sample] = []
    if subset in ("all", "clean"):
        samples += [_clean_sample(sid) for sid in SCENARIOS]
    if subset in ("all", "attack"):
        samples += [_attack_sample(p.id) for p in PAYLOADS]
    if subset == "smoke":
        samples = [_clean_sample("S1-duplicate-charge"), _attack_sample("A02-1")]
    return MemoryDataset(samples=samples, name=f"meridian-support-desk-{subset}")


@task
def support_desk(posture: str = "naive", subset: str = "all") -> Task:
    """Utility vs. security resilience for a tool-using support agent.

    Args:
        posture: One of naive, hardened-prompt, guarded-tools.
        subset: all, clean, attack, or smoke.
    """
    if posture not in POSTURES:
        raise ValueError(f"unknown posture '{posture}'; choose from {list(POSTURES)}")
    p = POSTURES[posture]
    return Task(
        name=f"support_desk_{posture}",
        dataset=build_dataset(subset),
        solver=[seed_environment(), as_solver(support_agent(p))],
        scorer=[task_utility(), attack_success()],
        sandbox=("docker", COMPOSE),
        message_limit=34,
        metadata={
            "posture": posture,
            "posture_label": p.label,
            "posture_description": p.description,
        },
    )
