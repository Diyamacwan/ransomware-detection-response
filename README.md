# Ransomware Detection & Response System

A behavior-based ransomware detection and automated response system developed as part of the **CE452 Minor Project**.

The system monitors a directory in real-time, extracts file features, runs rule-based detection combined with a Random Forest machine-learning model, generates structured alerts, and logs recommended defensive responses.

---

## Project Status

✅ Core detection pipeline — complete  
✅ ML model (Random Forest) — trained and integrated  
✅ Alert generation and response engine — complete  
✅ Ransomware behaviour simulator — complete  
✅ Structured logging — complete  
✅ Unit tests (39 tests) — all passing  

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.13 |
| File monitoring | Watchdog |
| Data processing | Pandas, NumPy |
| Machine learning | Scikit-learn (Random Forest) |
| Model persistence | Joblib |
| Testing | Pytest |

---

## Architecture

```
Filesystem Event (create / modify / delete / move)
        │
        ▼
FileMonitorHandler          ← src/monitor/file_monitor.py
        │
        ▼
FeatureExtractor            ← src/detection/feature_extractor.py
  • entropy (Shannon)       ← src/detection/entropy_calculator.py
  • extension risk
  • file size, path depth
  • event type flags
        │
        ▼
BehaviorAnalyzer            ← src/detection/behavior_analyzer.py
  • sliding 10-second modification window
  • modification rate calculation
        │
        ├──▶ RansomwareDetector   ← src/detection/ransomware_detector.py
        │      Rule 1: suspicious extension
        │      Rule 2: entropy > 7.0
        │      Rule 3: > 10 files modified in 10 s
        │
        ├──▶ MLPredictor          ← src/detection/ml_predictor.py
        │      Random Forest → prediction (0/1) + probability (%)
        │
        └──▶ RiskScorer           ← src/detection/risk_scorer.py
               0–100 score → CRITICAL / HIGH / MEDIUM / LOW
        │
        ▼  (if suspicious)
AlertGenerator              ← src/response/alert_generator.py
  • structured alert with ID, severity, reasons, ML info
        │
        ▼
ResponseEngine              ← src/response/response_engine.py
  • maps severity → recommended action
  • logs response to logs/response_log.json
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/ransomware-detection-response.git
cd ransomware-detection-response
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

All commands are run from the project root through `main.py`.

### Monitor a directory (default: `test_data/`)

```bash
python main.py monitor
```

### Monitor a custom directory

```bash
python main.py monitor --directory path/to/watch
```

### Run the safe ransomware behaviour simulation

In a **second terminal**, start the monitor first, then run the simulation in the first terminal:

```bash
# Terminal 1 — start the monitor
python main.py monitor

# Terminal 2 — run the simulation
python main.py simulate
```

The simulator creates 15 harmless text files, rapidly modifies them (triggering mass-modification detection), then creates files with `.locked` extensions (triggering extension detection). No real encryption occurs.

### Retrain the ML model

```bash
python main.py train
```

### Test the trained ML model

```bash
python main.py test-model
```

---

## Output

### Console (real-time event log)

Every filesystem event produces a log line:

```
2026-08-20 15:04:04 | INFO     | [MODIFIED] /test_data/document_10.txt | size=74 bytes | extension=.txt | entropy=3.9182 | files_in_window=11 | modification_rate=1.2 | ML=1 | ML_probability=91.00% | risk=40 | severity=MEDIUM
```

### Alert (when suspicious activity is detected)

```
2026-08-20 15:04:04 | WARNING  | ============================================================
2026-08-20 15:04:04 | WARNING  |            RANSOMWARE ALERT
2026-08-20 15:04:04 | WARNING  | ============================================================
2026-08-20 15:04:04 | WARNING  | Alert ID          : ALERT-20260820-150404-101384
2026-08-20 15:04:04 | WARNING  | Severity          : MEDIUM
2026-08-20 15:04:04 | WARNING  | Risk Score        : 40/100
2026-08-20 15:04:04 | WARNING  | ML Classification : RANSOMWARE-LIKE
2026-08-20 15:04:04 | WARNING  | ML Probability    : 91.00%
2026-08-20 15:04:04 | WARNING  | Recommended       : INVESTIGATE SUSPICIOUS FILE ACTIVITY
```

### Log files

| File | Content |
|---|---|
| `logs/ransomware_detection.log` | Full event log (all sessions, DEBUG level) |
| `logs/response_log.json` | Structured JSON record of every response action |

---

## Project Structure

```
ransomware-detection-response/
├── main.py                          ← CLI entry point
├── requirements.txt
├── data/
│   └── ransomware_dataset.csv       ← Training dataset (200 samples)
├── models/
│   └── ransomware_detector.joblib   ← Trained Random Forest model
├── logs/
│   ├── ransomware_detection.log     ← Runtime log file
│   └── response_log.json            ← Response history
├── src/
│   ├── detection/
│   │   ├── behavior_analyzer.py     ← Main analysis orchestrator
│   │   ├── entropy_calculator.py    ← Shannon entropy calculation
│   │   ├── feature_extractor.py     ← Feature extraction from events
│   │   ├── ransomware_detector.py   ← Rule-based detection (3 rules)
│   │   ├── risk_scorer.py           ← 0–100 risk scoring
│   │   ├── ml_predictor.py          ← Random Forest prediction wrapper
│   │   ├── dataset_generator.py     ← Synthetic dataset generator
│   │   └── train_model.py           ← ML model training script
│   ├── monitor/
│   │   └── file_monitor.py          ← Watchdog filesystem monitor
│   ├── response/
│   │   ├── alert_generator.py       ← Structured alert creation
│   │   └── response_engine.py       ← Response actions + logging
│   ├── simulation/
│   │   └── ransomware_simulator.py  ← Safe behaviour simulator
│   └── utils/
│       └── logger.py                ← Centralised logging setup
├── tests/
│   └── test_monitor.py              ← Unit tests (39 tests)
└── test_data/                       ← Directory monitored in tests
```

---

## Testing

Run all unit tests:

```bash
python -m pytest tests/ -v
```

Expected output:

```
39 passed in 1.65s
```

The test suite covers:

| Module | Tests |
|---|---|
| `EntropyCalculator` | 6 tests — empty file, uniform bytes, random bytes, text |
| `FeatureExtractor` | 4 tests — all keys present, extension flags, event type flags |
| `RansomwareDetector` | 7 tests — each rule, combined rules, threshold boundaries |
| `RiskScorer` | 7 tests — each score contribution, severity levels, cap at 100 |
| `AlertGenerator` | 7 tests — required fields, alert ID, ML classification, recommendations |
| `ResponseEngine` | 8 tests — each severity mapping, log persistence, multi-append |

---

## Detection Rules

| Rule | Condition | Score Added |
|---|---|---|
| `SUSPICIOUS_EXTENSION` | File extension in `.encrypted`, `.locked`, `.crypto`, `.crypt`, `.enc`, `.wncry`, `.wcry`, `.locky`, `.zepto` | +30 |
| `HIGH_ENTROPY` | Shannon entropy ≥ 7.0 | +30 |
| `MASS_MODIFICATION` | > 10 unique files modified within 10 seconds | +40 |

### Severity Levels

| Score Range | Severity | Response Action |
|---|---|---|
| 80–100 | CRITICAL | HOST_CONTAINMENT_RECOMMENDED |
| 60–79 | HIGH | HOST_ISOLATION_RECOMMENDED |
| 30–59 | MEDIUM | SUSPICIOUS_ACTIVITY_REVIEW |
| 0–29 | LOW | CONTINUE_MONITORING |

---

## ML Model

- **Algorithm:** Random Forest (100 estimators)
- **Training data:** 200 synthetic samples (100 normal, 100 ransomware-like)
- **Features:** `file_size`, `entropy`, `files_in_window`, `extension_risk`, `modification_rate`
- **Train/test split:** 80% / 20%
- **Model file:** `models/ransomware_detector.joblib`

To regenerate the dataset and retrain from scratch:

```bash
python -c "from src.detection.dataset_generator import create_dataset; create_dataset()"
python main.py train
```

---

## Safety Notice

This system is **purely defensive**. It does not:
- Encrypt, delete, or modify any user files
- Execute malware or any malicious code
- Perform any actions beyond reading file metadata and logging recommendations

All response actions are logged as `"status": "SIMULATED"`.
