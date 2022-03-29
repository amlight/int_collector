  INT Collector Release Plan

    Version 1.0 (ETA: 03/31/2022)

- Support capture of INT reports version 1.0
- Support capture of millions of packets per second
- Support for specialized running instances for interface/queue/vlan counters and queue occupancy/hop delay thresholds via CLI
- Store counter and thresholds on Influxdb
- Make code public via Github
- Support for tracking number of INT reports received vs INT reports processed
- Support for tracking number of INT reports damaged

    Version 1.1 (ETA: 04/30/2022)

- Support for specialized running instances for interface/queue/vlan counters and queue occupancy/hop delay thresholds via config file
- Support a watchdog to monitor instances running
- Support for tracking reports sequence number
- Support a running mode to evaluate the INT reports only
- Full support for up to 10 switches adding INT metadata

    Version 2.0 (ETA: 07/31/2022)

- Support separated XDP files for performance and scalability
- Support for sending consolidated reports via message broker
- Moving persistency to operate via message broker
- Support for IP monitoring when needed
- Support for receiving instructions via message broker
- Support for logging events
- Support for intra-domain BAPM

    Version 2.1 (ETA: 10/31/2022)

- Support for inter-domain BAPM

    Version 3.0 (ETA: 03/31/2023)

- tcpdump dissector for INT v1.0
- Scalability by randomizing telemetry Ethernet header's values and sending back to network
- TBD