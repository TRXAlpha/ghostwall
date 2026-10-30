#!/bin/bash
# Resume the malware pipeline: tuned model, then evaluate both models. Baseline is already trained.
cd "$(dirname "$0")"
.venv/Scripts/python -u scanner/train_gbm.py tuned > pe_tuned.log 2>&1
.venv/Scripts/python -u scanner/eval_pe.py models/pe_baseline.lgb models/pe_tuned.lgb > pe_eval.log 2>&1
