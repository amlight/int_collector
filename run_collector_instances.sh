#!/bin/bash

INTF_1="intel-10g-02"
INTF_2="intel-10g-03"

python InDBClient.py $INTF_1 --run-counter-mode-only=1 --database=INT-Counters &
python InDBClient.py $INTF_2 --run-threshold-mode-only=1 --database=INT-Thresholds &