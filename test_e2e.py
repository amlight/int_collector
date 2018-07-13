import pytest
import subprocess
import time
import os
import signal
from scapy.all import *
from influxdb import InfluxDBClient

sys.path.insert(0, './benchmark')
from INTReport import TelemetryReport, INT

inif = "int_veth_0"
outif = "int_veth_1"
subp = None

def start_client(cmd):
    global subp 
    try:
        subp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            universal_newlines=True)
    except Exception as e:
        print e
        return None

    p = subp.stdout.readline()
    assert (subp.poll() == None), "Error loading XDP program"

    time.sleep(0.5)
        
@pytest.fixture
def setup_veth():
    os.system("ip link add %s type veth peer name %s" % (inif, outif))
    os.system("ip link set dev %s up" % inif)
    os.system("ip link set dev %s up" % outif)
    os.system("systemctl restart influxdb")
    time.sleep(0.5)
    yield
    
    if (subp != None):
        subp.send_signal(signal.SIGINT)
        time.sleep(0.5)
    os.system("ip link del %s" % inif)

def end_to_end_influxdb(cmd):    
    start_client(cmd)
    assert (subp != None), "Fail subprocess to load XDP program"

    p0 = Ether()/ \
        IP(tos=0x17<<2)/ \
        UDP(sport=5000, dport=54321)/ \
        TelemetryReport(ingressTimestamp= 1524138290)/ \
        Ether()/ \
        IP(src="10.0.0.1", dst="10.0.0.2")/ \
        UDP(sport=5000, dport=5000)/ \
        INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
            INTMetadata= [4, 2<<16| 3, 400, 5<<16| 600, 700, 1524234560, 5<<16| 1000, 1,
                          5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234561, 5<<16| 10, 1,
                          6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234562, 5<<16| 10, 1],
                          originDSCP=14)
    # no significant changes
    p1 = Ether()/ \
    IP(tos=0x17<<2)/ \
    UDP(sport=5000, dport=54321)/ \
    TelemetryReport(ingressTimestamp= 1524138290)/ \
    Ether()/ \
    IP(src="10.0.0.1", dst="10.0.0.2")/ \
    UDP(sport=5000, dport=5000)/ \
    INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
        INTMetadata= [4, 2<<16| 3, 410, 5<<16| 600, 700, 1524234561, 5<<16| 1005, 1,
                      5, 2<<16| 3, 5, 5<<16| 6, 7, 1524234562, 5<<16| 10, 1,
                      6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234563, 5<<16| 10, 1],
                      originDSCP=14)
    # significant changes
    p2 = Ether()/ \
        IP(tos=0x17<<2)/ \
        UDP(sport=5000, dport=54321)/ \
        TelemetryReport(ingressTimestamp= 1524138300)/ \
        Ether()/ \
        IP(src="10.0.0.1", dst="10.0.0.2")/ \
        UDP(sport=5000, dport=5000)/ \
        INT(insCnt=8, totalHopCnt=3, ins=(1<<7|1<<6|1<<5|1<<4|1<<3|1<<2|1<<1|1)<<8,
            INTMetadata= [4, 5<<16| 3, 4, 5<<16| 6, 7, 1524234570, 5<<16| 10, 1000,
            5, 2<<16| 3, 4, 5<<16| 6, 7, 1524234571, 5<<16| 10, 1,
            6, 2<<16| 3, 4, 5<<16| 6, 7, 1524234572, 5<<16| 10, 1],
            originDSCP=14)

    client = InfluxDBClient(host="localhost", database="INTdatabase")

    for p in [p0, p1]:
        # the value should keep same as p0
        sendp(p0, iface=inif)
        time.sleep(1)
        assert len(client.get_list_measurements()) == 13

        r = client.query("select * from \"flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=4\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=4', None)': [{u'value': 400, u'time': 1524234560}]})"
        r = client.query("select * from \"flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=5', None)': [{u'value': 4, u'time': 1524234561}]})"
        r = client.query("select * from \"flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=6\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=6', None)': [{u'value': 4, u'time': 1524234562}]})"
     
        r = client.query("select * from \"port_tx_utilize,sw_id=4,port_id=3\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'port_tx_utilize,sw_id=4,port_id=3', None)': [{u'value': 1, u'time': 1524234560}]})"
        r = client.query("select * from \"port_tx_utilize,sw_id=5,port_id=3\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'port_tx_utilize,sw_id=5,port_id=3', None)': [{u'value': 1, u'time': 1524234561}]})"
        r = client.query("select * from \"port_tx_utilize,sw_id=6,port_id=3\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'port_tx_utilize,sw_id=6,port_id=3', None)': [{u'value': 1, u'time': 1524234562}]})"
     
        r = client.query("select * from \"queue_occupancy,sw_id=4,queue_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'queue_occupancy,sw_id=4,queue_id=5', None)': [{u'value': 600, u'time': 1524234560}]})"
        r = client.query("select * from \"queue_occupancy,sw_id=5,queue_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'queue_occupancy,sw_id=5,queue_id=5', None)': [{u'value': 6, u'time': 1524234561}]})"
        r = client.query("select * from \"queue_occupancy,sw_id=6,queue_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'queue_occupancy,sw_id=6,queue_id=5', None)': [{u'value': 6, u'time': 1524234562}]})"

        r = client.query("select * from \"queue_congestion,sw_id=4,queue_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'queue_congestion,sw_id=4,queue_id=5', None)': [{u'value': 1000, u'time': 1524234560}]})"
        r = client.query("select * from \"queue_congestion,sw_id=5,queue_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'queue_congestion,sw_id=5,queue_id=5', None)': [{u'value': 10, u'time': 1524234561}]})"
        r = client.query("select * from \"queue_congestion,sw_id=6,queue_id=5\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'queue_congestion,sw_id=6,queue_id=5', None)': [{u'value': 10, u'time': 1524234562}]})"

        r = client.query("select * from \"flow_stat,10.0.0.1:5000->10.0.0.2:5000,proto=17\"", epoch='ns')
        assert str(r) == "ResultSet({'(u'flow_stat,10.0.0.1:5000->10.0.0.2:5000,proto=17', None)': [{u'path': u'6:5:4', u'flow_latency': 408, u'time': 1524138290}]})"


    sendp(p2, iface=inif)
    time.sleep(1)
    assert len(client.get_list_measurements()) == 13
    r = client.query("select * from \"flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=4\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=4', None)': [{u'value': 400, u'time': 1524234560}, {u'value': 4, u'time': 1524234570}]})"
    r = client.query("select * from \"flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=5', None)': [{u'value': 4, u'time': 1524234561}]})"
    r = client.query("select * from \"flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=6\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'flow_hop_latency,10.0.0.1:5000->10.0.0.2:5000,proto=17,sw_id=6', None)': [{u'value': 4, u'time': 1524234562}]})"
 
    r = client.query("select * from \"port_tx_utilize,sw_id=4,port_id=3\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'port_tx_utilize,sw_id=4,port_id=3', None)': [{u'value': 1, u'time': 1524234560}, {u'value': 1000, u'time': 1524234570}]})"
    r = client.query("select * from \"port_tx_utilize,sw_id=5,port_id=3\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'port_tx_utilize,sw_id=5,port_id=3', None)': [{u'value': 1, u'time': 1524234561}]})"
    r = client.query("select * from \"port_tx_utilize,sw_id=6,port_id=3\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'port_tx_utilize,sw_id=6,port_id=3', None)': [{u'value': 1, u'time': 1524234562}]})"
 
    r = client.query("select * from \"queue_occupancy,sw_id=4,queue_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'queue_occupancy,sw_id=4,queue_id=5', None)': [{u'value': 600, u'time': 1524234560}, {u'value': 6, u'time': 1524234570}]})"
    r = client.query("select * from \"queue_occupancy,sw_id=5,queue_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'queue_occupancy,sw_id=5,queue_id=5', None)': [{u'value': 6, u'time': 1524234561}]})"
    r = client.query("select * from \"queue_occupancy,sw_id=6,queue_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'queue_occupancy,sw_id=6,queue_id=5', None)': [{u'value': 6, u'time': 1524234562}]})"

    r = client.query("select * from \"queue_congestion,sw_id=4,queue_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'queue_congestion,sw_id=4,queue_id=5', None)': [{u'value': 1000, u'time': 1524234560}, {u'value': 10, u'time': 1524234570}]})"
    r = client.query("select * from \"queue_congestion,sw_id=5,queue_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'queue_congestion,sw_id=5,queue_id=5', None)': [{u'value': 10, u'time': 1524234561}]})"
    r = client.query("select * from \"queue_congestion,sw_id=6,queue_id=5\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'queue_congestion,sw_id=6,queue_id=5', None)': [{u'value': 10, u'time': 1524234562}]})"

    r = client.query("select * from \"flow_stat,10.0.0.1:5000->10.0.0.2:5000,proto=17\"", epoch='ns')
    assert str(r) == "ResultSet({'(u'flow_stat,10.0.0.1:5000->10.0.0.2:5000,proto=17', None)': [{u'path': u'6:5:4', u'flow_latency': 408, u'time': 1524138290}, {u'path': u'6:5:4', u'flow_latency': 12, u'time': 1524138300}]})"

def test_e2e_indb_threshold(setup_veth):
    cmd = ["python", "InDBClient.py", "-t", outif]
    end_to_end_influxdb(cmd)

def test_e2e_indb_interval(setup_veth):
    cmd = ["python", "InDBClient.py", "-t", "-e", "INTERVAL", outif]
    end_to_end_influxdb(cmd)

def test_e2e_indb_non_perf(setup_veth):
    cmd = ["python", "InDBClient.py", "-t", "--non_perf", outif]
    end_to_end_influxdb(cmd)
