"""Shared helpers for the evaluation tests (fixtures only; no real data)."""
import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "evaluation" / "datasets" / "ps010-eval-v1" / "dataset.json"

T0 = "2026-10-28T12:00:00+00:00"


def shipped_raw() -> dict:
    return json.loads(DATASET_PATH.read_text(encoding="utf-8"))


def edited(mutate):
    raw = copy.deepcopy(shipped_raw())
    mutate(raw)
    return raw


def case_of(raw: dict, case_id: str) -> dict:
    return next(c for c in raw["cases"] if c["case_id"] == case_id)


def reference_case(**overrides) -> dict:
    """A VALID reference-tier case used only to exercise the validator and runner paths.

    The source text says so: this is a test fixture, never an entry in the shipped dataset.
    """
    case = {
        "case_id": "ref-fixture-001",
        "tier": "reference",
        "category": "known_tor_exit",
        "ip": "11.10.10.1",
        "observed_at": T0,
        "expected_label": "Known Tor exit",
        "reference": {
            "source": "Test-fixture operator attestation (not a real source)",
            "source_type": "operator_attestation",
            "retrieved_at": T0,
            "temporal_support": "current-only",
            "label_basis": "Fixture used by the validator tests; asserts nothing about any real host.",
            "confidence": "medium",
            "limitations": ["Fixture only."],
            "independent_of_classifier_sources": True,
        },
    }
    for key, value in overrides.items():
        if key == "reference":
            case["reference"].update(value)
        else:
            case[key] = value
    return case


def with_cases(*cases) -> dict:
    return edited(lambda raw: raw["cases"].extend(cases))


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(f"script_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
