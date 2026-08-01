#!/usr/bin/env python3
"""Run the support-desk suite across defensive postures (and optionally models).

    uv run python scripts/run_eval.py --subset smoke --postures naive
    uv run python scripts/run_eval.py --models google/gemini-3.6-flash

Every (model, posture) pair is one Inspect eval over the same 32 samples.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, Path(__file__).resolve().parent.parent.as_posix())

from inspect_ai import eval as inspect_eval  # noqa: E402

from evalsuite.task import support_desk  # noqa: E402
from evalsuite.tools import POSTURES  # noqa: E402

# The Google provider reads GOOGLE_API_KEY; this environment supplies GEMINI_API_KEY.
# Drop the alias afterwards, or the client logs a warning on every single call.
if "GEMINI_API_KEY" in os.environ:
    os.environ.setdefault("GOOGLE_API_KEY", os.environ["GEMINI_API_KEY"])
    os.environ.pop("GEMINI_API_KEY", None)
# Moonshot is reached through Inspect's OpenAI-compatible provider.
os.environ.setdefault("MOONSHOT_BASE_URL", "https://api.moonshot.ai/v1")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["openai-api/moonshot/kimi-k3"])
    ap.add_argument("--postures", nargs="+", default=list(POSTURES))
    ap.add_argument("--subset", default="all", choices=["all", "clean", "attack", "smoke"])
    ap.add_argument("--log-dir", default="logs")
    ap.add_argument("--max-connections", type=int, default=6)
    ap.add_argument("--max-sandboxes", type=int, default=6)
    ap.add_argument("--retry-on-error", type=int, default=2)
    # A hung provider connection would otherwise stall a whole run: under the guarded
    # posture the agent burns many turns arguing with the policy engine, and a stalled
    # HTTP call has no natural end. These caps bound each sample instead.
    ap.add_argument("--time-limit", type=int, default=600)
    ap.add_argument("--working-limit", type=int, default=300)
    args = ap.parse_args()

    tasks = []
    for posture in args.postures:
        if posture not in POSTURES:
            raise SystemExit(f"unknown posture {posture!r}; choose from {list(POSTURES)}")
        tasks.append(support_desk(posture=posture, subset=args.subset))

    for model in args.models:
        slug = model.replace("/", "_").replace(".", "-")
        print(f"\n=== {model} · postures={args.postures} · subset={args.subset} ===")
        inspect_eval(
            tasks,
            model=model,
            log_dir=f"{args.log_dir}/{slug}",
            max_connections=args.max_connections,
            max_sandboxes=args.max_sandboxes,
            retry_on_error=args.retry_on_error,
            time_limit=args.time_limit,
            working_limit=args.working_limit,
            fail_on_error=0.25,
            log_level="warning",
            display="plain",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
