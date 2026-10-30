#!/bin/bash
# waits for the vectorizer, then trains the paper-config baseline and our tuned model, then evaluates both
cd "$(dirname "$0")"
while [ ! -f data/ember2024/vec/train.meta.parquet ]; do sleep 30; done
.venv/Scripts/python -u scanner/train_gbm.py baseline > pe_baseline.log 2>&1
.venv/Scripts/python -u scanner/train_gbm.py tuned > pe_tuned.log 2>&1
.venv/Scripts/python -u scanner/eval_pe.py models/pe_baseline.lgb models/pe_tuned.lgb > pe_eval.log 2>&1
