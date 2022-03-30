#########
Changelog
#########
All notable changes to the INT Collector will be documented in this file.


[1.0] - 2022-03-30
******************
This is the first release of the INT Collector.

Added
=====
- Collects INT reports following the INT 1.0 specification.
- Collects INT reports exported by NoviFlow switches.
- Developed using eBPF/XDP to capture millions of INT reports per second.
- Support interface, queue, and VLAN bandwidth utilization monitoring.
- Supports specialized running instances for interface/queue/vlan counters and queue occupancy/hop delay thresholds via CLI.
- Stores counters and thresholds on Influxdb.
- Support for tracking number of received vs. processed INT reports.
- Support for tracking number of corrupted INT reports.
- Created two Grafana dashboards to display data collected.

Known Issues
============
- It doesn't handle connection issues with Influxdb