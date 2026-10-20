#!/bin/sh
set -e
cd "$(dirname "$0")/experiments"
python3 ../tests/test_interop.py
python3 e1_seizure_matrix.py  > ../results/e1_log.txt
python3 e2_crash.py           > ../results/e2_log.txt
python3 e3_robustness.py      > ../results/e3_log.txt
python3 e4_bench.py           > ../results/e4_log.txt
[ -f ../results/e5_rtt_samples.json ] || python3 e5_rtt_measure.py 100 > ../results/e5_log.txt
python3 e6_models.py          > ../results/e6_log.txt
python3 e7_composition.py     > ../results/e7_log.txt
python3 e8_exposure.py        > ../results/e8_log.txt
python3 make_tables.py
python3 make_figs.py
