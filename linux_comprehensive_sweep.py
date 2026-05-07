"""
Run comprehensive Linux LogGPT experiments by sweeping top_k, train_samples, and seed.

Fixed arguments:
  dataset = Linux
  window_size = 60
  step_size = 30
  logGPT_episode = 5
  init_num_epochs = 5
  device = cpu
  preprocessing = False
  building_vocab = False
  download_datasets = False

Variable arguments:
  top_k in {1, 3, 5, 7, 13, 20}
  train_samples in {100, 300, 500}
  seed in {3, 5, 7}

Total runs: 6 * 3 * 3 = 54

Run from repository root:
  python linux_comprehensive_sweep.py
"""

from __future__ import annotations

import argparse
import itertools
import subprocess
import sys
from pathlib import Path


TOP_K_VALUES = [1, 3, 5, 7, 13, 20]
TRAIN_SAMPLE_VALUES = [100, 300, 500]
SEED_VALUES = [3, 5, 7]


def str_bool(value: bool) -> str:
    """Return bool as lowercase string for argparse-style project flags."""
    return "False" if value is False else "True"


def build_command(top_k: int, train_samples: int, seed: int) -> list[str]:
    return [
        sys.executable,
        "main.py",
        "Linux",
        "--device",
        "cpu",
        "--window_size",
        "60",
        "--step_size",
        "30",
        "--logGPT_episode",
        "5",
        "--init_num_epochs",
        "5",
        "--preprocessing",
        str_bool(False),
        "--building_vocab",
        str_bool(False),
        "--download_datasets",
        str_bool(False),
        "--top_k",
        str(top_k),
        "--train_samples",
        str(train_samples),
        "--seed",
        str(seed),
        "--use_semantic_tokens",
        str_bool(False)
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Linux LogGPT comprehensive testing sweep."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing them.",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue running remaining experiments if one command fails.",
    )
    parser.add_argument(
        "--start-at",
        type=int,
        default=1,
        help="1-based run number to start at. Useful for resuming a sweep.",
    )
    parser.add_argument(
        "--stop-at",
        type=int,
        default=None,
        help="1-based run number to stop at. Useful for running a single experiment.",
    )
    args = parser.parse_args()

    repo_root = Path.cwd()
    main_py = repo_root / "main.py"
    if not main_py.exists():
        raise FileNotFoundError(
            "main.py was not found. Run this script from the LogGPT-MITRE repo root."
        )

    experiments = list(
        itertools.product(TOP_K_VALUES, TRAIN_SAMPLE_VALUES, SEED_VALUES)
    )
    total = len(experiments)

    print(f"Total experiments: {total}")
    print("Fixed config: Linux | W60/S30 | epochs=5 | episodes=5 | cpu")
    print("download_datasets=False | preprocessing=False | building_vocab=False")
    print()

    for run_number, (top_k, train_samples, seed) in enumerate(experiments, start=1):
        if run_number < args.start_at:
            continue
        if args.stop_at is not None and run_number > args.stop_at:
            break

        cmd = build_command(top_k=top_k, train_samples=train_samples, seed=seed)

        print("=" * 100)
        print(
            f"Run {run_number}/{total} | "
            f"top_k={top_k} | train_samples={train_samples} | seed={seed}"
        )
        print(" ".join(cmd))
        print("=" * 100)

        if args.dry_run:
            continue

        result = subprocess.run(cmd)

        if result.returncode != 0:
            print(
                f"Run {run_number} failed with exit code {result.returncode}: "
                f"top_k={top_k}, train_samples={train_samples}, seed={seed}"
            )
            if not args.continue_on_error:
                sys.exit(result.returncode)

    print("All requested experiments completed.")


if __name__ == "__main__":
    main()
