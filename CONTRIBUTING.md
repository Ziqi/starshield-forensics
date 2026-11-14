# Contributing to `starshield-forensics`

Thank you for contributing to `starshield-forensics`. Because this toolkit is used in pre-action payment-dispute triage and digital forensics validation, all contributions must preserve **stdlib-only portability, memory-bounded parsing, and evidentiary neutrality**.

## 1. Quick Development Setup (< 30 Seconds)

`starshield-forensics` requires **Python >= 3.10** and **zero external runtime dependencies**:

```bash
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics

# Run unit, adversarial boundary, and canary-redaction tests under strict warnings
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -W error -m unittest discover -s tests -v

# Run deterministic stdlib parser fuzzing harness (2,500 mutated byte vectors)
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -W error tests/fuzz_parsers.py --stdlib --iterations 2500

# Run the 24-case deterministic benchmark
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 benchmark/benchmark_suite.py

# Build and verify bit-for-bit reproducible single-file zipapp
python3 scripts/build_reproducible.py --verify
```

## 2. Developer Certificate of Origin (DCO 1.1) & Licensing

All contributions are licensed under the **MIT License** (`LICENSE`). Every commit MUST include a `Signed-off-by:` trailer (`git commit -s`) certifying compliance with the [Developer Certificate of Origin v1.1](https://developercertificate.org/):

```text
Signed-off-by: Random J Developer <random@developer.example.org>
```

**Clean-Room Fixture Rule:** Never submit real client data, live case artifacts, or personal identifiable information (PII). All test vectors and fixtures MUST be 100% synthetic specification vectors (e.g., ISO-13616 official example IBANs and RFC test chunks).

## 3. Coding Standards & Automated Enforcement

- **Style Guide:** Python code follows **PEP 8** with explicit type annotations (`from __future__ import annotations`).
- **Automated Linting, Static Security Analysis & Continuous Fuzzing (Enforced in CI):**
  - `ruff check starshield tests benchmark scripts` (0 lint errors required)
  - `bandit -q -r starshield scripts` (0 Low/Medium/High security findings required)
  - `python3 -W error -m unittest discover -s tests -v` (maximally strict warning enforcement)
  - `python3 -W error tests/fuzz_parsers.py --stdlib --iterations 2500` + `ClusterFuzzLite / Atheris` (`cflite.yml`)
- **Zero Runtime Dependencies:** Runtime modules under `starshield/` MUST import exclusively from the Python >= 3.10 standard library and perform zero outbound network calls.

## 4. Mandatory Automated Testing & Coverage Policy

1. **New Functionality Policy (`test_policy_mandated`):** Every pull request introducing major or minor functionality MUST add automated positive and malformed-input unit tests in `tests/test_adversarial.py`.
2. **Bug-Fix Regression Policy (`regression_tests_added50`):** Every bug fix (100% target, strictly >= 50% minimum) MUST include a deterministic regression test reproducing the prior defect and verifying the fix.
3. **Statement Coverage Gate (`test_statement_coverage80`):** Automated CI enforces **>= 80% statement coverage** across `starshield/` via FLOSS `coverage.py` (`coverage run -m unittest discover -s tests && coverage report --include="starshield/*" --fail-under=80`).
