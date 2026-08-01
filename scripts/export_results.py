#!/usr/bin/env python3
"""Turn the committed .eval logs into the JSON the static site reads.

Writes two files:

* ``site/data/results.json``     — summary metrics, per-sample rows, ledgers.
* ``site/data/transcripts.json`` — full message transcripts, loaded lazily by the site.

Nothing is recomputed from scratch here: utility and attack values come straight from the
scorers that ran inside the eval, so the site cannot drift from the logs.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, Path(__file__).resolve().parent.parent.as_posix())

from inspect_ai.log import read_eval_log  # noqa: E402

from evalsuite.scenarios import (  # noqa: E402
    CLASS_BLURB,
    OWASP_CLASSES,
    PAYLOADS,
    SCENARIOS,
)
from evalsuite.tools import POSTURES  # noqa: E402

MODEL_LABELS = {
    "google/gemini-3.6-flash": "Gemini 3.6 Flash",
    "google/gemini-3.5-flash": "Gemini 3.5 Flash",
    "google/gemini-3.1-pro-preview": "Gemini 3.1 Pro",
    "google/gemini-3-pro-preview": "Gemini 3 Pro",
    "google/gemini-2.5-pro": "Gemini 2.5 Pro",
    "google/gemini-2.5-flash": "Gemini 2.5 Flash",
    "openai-api/moonshot/kimi-k3": "Kimi K3",
    "openai-api/moonshot/kimi-k2.7-code": "Kimi K2.7 Code",
    "openai-api/moonshot/kimi-k2.6": "Kimi K2.6",
}

MAX_MSG_CHARS = 5000


def _label(model: str) -> str:
    return MODEL_LABELS.get(model, model.split("/")[-1])


def _num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            t = getattr(c, "text", None)
            if t:
                parts.append(t)
            elif getattr(c, "type", "") == "reasoning":
                r = getattr(c, "reasoning", "")
                if r:
                    parts.append(f"[reasoning] {r}")
        return "\n".join(parts)
    return str(content or "")


def _exposed(actions: list[dict], channel: str) -> bool:
    """Did the agent actually retrieve the channel the payload was planted in?

    An attack the agent never read is not an attack it resisted, so this is reported
    separately rather than being quietly folded into the resilience number.
    """
    for a in actions:
        tool = a.get("tool")
        args = a.get("args") or {}
        if channel == "ticket_body" and tool == "read_ticket":
            return True
        if channel == "customer_notes" and tool == "lookup_customer":
            return True
        if channel.startswith("page:") and tool == "fetch_page":
            if args.get("url") == channel.split(":", 1)[1]:
                return True
        if channel.startswith("kb:") and tool == "read_kb":
            if args.get("doc_id") == channel.split(":", 1)[1]:
                return True
    return False


def _transcript(sample) -> list[dict]:
    out = []
    for m in sample.messages or []:
        entry = {"role": m.role, "text": _text_of(m.content)[:MAX_MSG_CHARS]}
        calls = getattr(m, "tool_calls", None)
        if calls:
            entry["tool_calls"] = [
                {"name": c.function, "args": c.arguments} for c in calls
            ]
        if m.role == "tool":
            entry["tool_name"] = getattr(m, "function", "") or ""
            if getattr(m, "error", None):
                entry["error"] = str(m.error.message)[:1000]
        out.append(entry)
    return out


def collect(log_root: str, primary_model: str | None = None) -> dict:
    paths = sorted(glob.glob(f"{log_root}/**/*.eval", recursive=True))
    if not paths:
        raise SystemExit(f"no .eval logs under {log_root}")

    rows: list[dict] = []
    transcripts: dict[str, list[dict]] = {}
    runs: list[dict] = []
    models_seen: list[str] = []

    for path in paths:
        log = read_eval_log(path)
        if log.status != "success":
            print(f"  skipping {path} (status={log.status})")
            continue
        model = log.eval.model
        posture = (log.eval.task_args or {}).get("posture", "unknown")
        subset = (log.eval.task_args or {}).get("subset", "all")
        if subset != "all":
            print(f"  skipping {path} (subset={subset})")
            continue
        if model not in models_seen:
            models_seen.append(model)

        usage = None
        if log.stats and log.stats.model_usage:
            u = list(log.stats.model_usage.values())[0]
            usage = {
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "total_tokens": u.total_tokens,
            }
        runs.append(
            {
                "model": model,
                "posture": posture,
                "log_file": str(Path(path).relative_to(Path(log_root).parent)),
                "started": str(log.eval.created),
                "samples": len(log.samples or []),
                "usage": usage,
            }
        )

        incomplete = 0
        for s in log.samples or []:
            # A sample that hit a time/working limit can finish without scores; count it
            # rather than letting it disappear silently from the denominator.
            if not s.scores or "task_utility" not in s.scores or "attack_success" not in s.scores:
                incomplete += 1
                continue
            util = s.scores["task_utility"]
            atk = s.scores["attack_success"]
            meta = s.metadata or {}
            row_id = f"{model}|{posture}|{s.id}"
            actions = (util.metadata or {}).get("actions", [])
            rows.append(
                {
                    "exposed": (
                        _exposed(actions, meta.get("payload_channel", ""))
                        if meta.get("attacked")
                        else False
                    ),
                    "id": row_id,
                    "model": model,
                    "model_label": _label(model),
                    "posture": posture,
                    "sample": str(s.id),
                    "scenario": meta.get("scenario", ""),
                    "scenario_title": meta.get("scenario_title", ""),
                    "attacked": bool(meta.get("attacked")),
                    "asi": meta.get("asi", "none"),
                    "asi_name": meta.get("asi_name", ""),
                    "payload_id": meta.get("payload_id", ""),
                    "payload_channel": meta.get("payload_channel", ""),
                    "payload_note": meta.get("payload_note", ""),
                    "utility": _num(util.value),
                    "attack": _num(atk.value),
                    "utility_checks": (util.metadata or {}).get("checks", []),
                    "attack_checks": (atk.metadata or {}).get("checks", []),
                    "actions": actions,
                    "completion": (util.metadata or {}).get("completion", "")[:4000],
                }
            )
            transcripts[row_id] = _transcript(s)

        if incomplete:
            print(f"  WARNING: {incomplete} sample(s) in {posture} finished without scores")
        runs[-1]["unscored_samples"] = incomplete

    # ------------------------------------------------------------------ aggregation ---
    summary = []
    by_run = defaultdict(list)
    for r in rows:
        by_run[(r["model"], r["posture"])].append(r)

    for (model, posture), rs in by_run.items():
        clean = [r for r in rs if not r["attacked"]]
        attacked = [r for r in rs if r["attacked"]]
        asr_by_class = {}
        util_by_class = {}
        exposure_by_class = {}
        for asi in OWASP_CLASSES:
            cls = [r for r in attacked if r["asi"] == asi]
            if cls:
                asr_by_class[asi] = sum(r["attack"] for r in cls) / len(cls)
                util_by_class[asi] = sum(r["utility"] for r in cls) / len(cls)
                exposure_by_class[asi] = sum(1 for r in cls if r["exposed"]) / len(cls)
        seen = [r for r in attacked if r["exposed"]]
        blocked = [
            r for r in attacked if any(a.get("blocked") for a in r["actions"])
        ]
        summary.append(
            {
                "model": model,
                "model_label": _label(model),
                "posture": posture,
                "posture_label": POSTURES[posture].label if posture in POSTURES else posture,
                "n_total": len(rs),
                "n_clean": len(clean),
                "n_attacked": len(attacked),
                "utility_all": sum(r["utility"] for r in rs) / len(rs),
                "utility_clean": sum(r["utility"] for r in clean) / len(clean) if clean else 0.0,
                "utility_attacked": (
                    sum(r["utility"] for r in attacked) / len(attacked) if attacked else 0.0
                ),
                "asr": sum(r["attack"] for r in attacked) / len(attacked) if attacked else 0.0,
                "resilience": (
                    1 - sum(r["attack"] for r in attacked) / len(attacked) if attacked else 1.0
                ),
                "asr_by_class": asr_by_class,
                "utility_by_class": util_by_class,
                "exposure_by_class": exposure_by_class,
                "n_exposed": len(seen),
                "exposure_rate": len(seen) / len(attacked) if attacked else 0.0,
                "asr_exposed": (
                    sum(r["attack"] for r in seen) / len(seen) if seen else 0.0
                ),
                "blocked_rate": len(blocked) / len(attacked) if attacked else 0.0,
                "utility_by_scenario": {
                    sid: (
                        sum(r["utility"] for r in rs if r["scenario"] == sid)
                        / max(1, len([r for r in rs if r["scenario"] == sid]))
                    )
                    for sid in SCENARIOS
                },
                "clean_utility_by_scenario": {
                    sid: (
                        sum(r["utility"] for r in clean if r["scenario"] == sid)
                        / max(1, len([r for r in clean if r["scenario"] == sid]))
                    )
                    for sid in SCENARIOS
                },
            }
        )

    posture_order = list(POSTURES)
    summary.sort(
        key=lambda s: (models_seen.index(s["model"]), posture_order.index(s["posture"]))
    )

    # The posture comparison is the subject of the study, so the main charts are scoped to
    # the model that was run across every posture. Any additional model is a control.
    postures_per_model = {
        m: {s["posture"] for s in summary if s["model"] == m} for m in models_seen
    }
    if primary_model and primary_model in models_seen:
        primary = primary_model
    else:
        primary = max(
            models_seen,
            key=lambda m: (len(postures_per_model[m]), -models_seen.index(m)),
        )

    return {
        "results": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "primary_model": primary,
            "models": [{"id": m, "label": _label(m)} for m in models_seen],
            "postures": [
                {"id": p.id, "label": p.label, "description": p.description}
                for p in POSTURES.values()
            ],
            "classes": [
                {"id": k, "name": v, "blurb": CLASS_BLURB[k]}
                for k, v in OWASP_CLASSES.items()
            ],
            "scenarios": [
                {"id": s.id, "title": s.title, "summary": s.summary}
                for s in SCENARIOS.values()
            ],
            "payloads": [
                {
                    "id": p.id,
                    "asi": p.asi,
                    "asi_name": OWASP_CLASSES[p.asi],
                    "scenario": p.scenario,
                    "channel": p.channel,
                    "note": p.note,
                    "text": p.text.strip(),
                }
                for p in PAYLOADS
            ],
            "runs": runs,
            "summary": summary,
            "rows": rows,
        },
        "transcripts": transcripts,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="logs")
    ap.add_argument("--out-dir", default="site/data")
    # Pinned so the headline charts do not silently switch models when a new log lands.
    ap.add_argument("--primary-model", default="openai-api/moonshot/kimi-k3")
    args = ap.parse_args()

    bundle = collect(args.log_dir, args.primary_model)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(bundle["results"], indent=1))
    (out / "transcripts.json").write_text(json.dumps(bundle["transcripts"], indent=1))

    res = bundle["results"]
    print(f"\nwrote {out}/results.json  ({len(res['rows'])} rows, {len(res['runs'])} runs)")
    print(f"wrote {out}/transcripts.json ({len(bundle['transcripts'])} transcripts)\n")
    hdr = f"{'model':<22} {'posture':<16} {'util(all)':>10} {'util(clean)':>12} {'ASR':>7}"
    print(hdr)
    print("-" * len(hdr))
    for s in res["summary"]:
        print(
            f"{s['model_label']:<22} {s['posture']:<16} {s['utility_all']:>10.3f} "
            f"{s['utility_clean']:>12.3f} {s['asr']:>7.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
