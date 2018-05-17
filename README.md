# BPFCollector
A high-performance collector to process INT Telemetry reports, and send data to database servers such as Prometheus and InfluxDB. 
Currently, BPFCollector supports [Telemetry report v0.5](https://github.com/p4lang/p4-applications/tree/master/docs), and [INT spec v0.5](https://github.com/p4lang/p4-applications/tree/master/docs) with TCP/UDP encapsulation.  
`BPFCollector` use [eBPF](https://www.iovisor.org/technology/ebpf) and [XDP](https://www.iovisor.org/technology/xdp), which require recent linux kernel. For best practice, kernel version >= v4.14 should be used.
# Installation

* Install Ubuntu VM with kernel version >= 4.14. Our test uses Ubuntu 18.04 64 bit with kernel v4.15.

* Install `bcc` from https://github.com/iovisor/bcc .

* Clone this repo:

 ``` shell
    $ git clone https://gitlab.com/tunv_ebpf/BPFCollector.git
 ```

* Install required python modules. There may be other missing modules beside `pyroute2`:

 ``` shell
    $ pip install pyroute2
 ```

* Install Prometheus and/or InfluxDB python client libraries, depending on the choice of the server:

 ``` shell
    $ pip install prometheus_client
    $ pip install influxdb
 ```
* [Optional] Enable `JIT` for eBPF, which makes code run faster (recommended):

 ``` shell
    $ sudo sysctl net/core/bpf_jit_enable=1
 ```

* [Optional] Install `Cython` to run the InfluxDB Client with option `--cython`, which is faster:

 ``` shell
    $ pip install Cython
 ```

* [Optional] create `veth` pair for testing. We can send INT Telemetry reports to one endpoint, and let `BPFCollector` listens to the reports at the other endpoint.

  ``` shell
    $ sudo ip link add veth_0 type veth peer name veth_1
    $ sudo ip link set dev veth0 up
    $ sudo ip link set dev veth1 up
  ```
* Run `BPFCollector` at the network interface that can listen to INT Telemetry reports. If you create `veth` pair above, you can send reports to `veth_0` and listen to reports at `veth_1`:

 ``` shell
    $ sudo python PTCollector.py veth_1 # For Prometheus
    $ sudo python InDBClient.py veth_1 # For InfluxDB
 ```
 
> Run the collector with `-h` option for more help. If there are any missing libraries, install them using `pip`. 
>
> INT Telemetry reports in pcap file can be created using `benchmark/INTReport.py`.
>
> If there are errors that eBPF program cannot load (such as _cannot allocate memory_), please ensure that the network interfaces the BPFCollector listens to has XDP support by current kernel. Check [here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp). 

# Server setup

* For Prometheus: Install and run Prometheus server from https://prometheus.io . Config the `.yml` file to scrape the `BPFCollector` client. Address should be `localhost` if Prometheus server and `BPFCollector` run on the same machine.

* For InfluxDB: InfluxDB python client requires InfluxDB sever v1.2.4:

``` shell
    $ wget https://dl.influxdata.com/influxdb/releases/influxdb_1.2.4_amd64.deb
    $ sudo dpkg -i influxdb_1.2.4_amd64.deb
    $ sudo systemctl start influxdb
```

> If InfluxDB server does not run in the same machine as the collector, we need to specify the server address with `-H` option when running `InDBClient.py`.


