package control

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zodirc/Vesper/internal/probe/amqpprobe"
	"github.com/zodirc/Vesper/internal/probe/imapprobe"
	"github.com/zodirc/Vesper/internal/probe/kafkaprobe"
	"github.com/zodirc/Vesper/internal/probe/mqttprobe"
	"github.com/zodirc/Vesper/internal/probe/natsprobe"
	"github.com/zodirc/Vesper/internal/probe/pop3probe"
	"github.com/zodirc/Vesper/internal/probe/rdpprobe"
	"github.com/zodirc/Vesper/internal/probe/telnetprobe"
	"github.com/zodirc/Vesper/internal/probe/udp"
	"github.com/zodirc/Vesper/internal/probe/vncprobe"
	"github.com/zodirc/Vesper/internal/rule"
)

func TestServiceProbesRecordTheProtocolWithoutAProduct(t *testing.T) {
	kafka := kafkaFrame()
	cases := []struct {
		name        string
		payload     []byte
		contentType string
		protocol    string
		target      *func(int) string
		match       func(map[string]any) bool
	}{
		{name: "telnet", payload: []byte{0xff, 0xfb, 0x01}, contentType: "text/plain", protocol: telnetprobe.Name, target: &telnetProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "telnet" && value["banner"] == nil
		}},
		{name: "pop3", payload: []byte("+OK ready\r\n"), contentType: "text/plain", protocol: pop3probe.Name, target: &pop3ProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "pop3" && value["reply_code"] == "+OK" && value["reply"] == "+OK ready"
		}},
		{name: "imap", payload: []byte("* OK ready\r\n"), contentType: "text/plain", protocol: imapprobe.Name, target: &imapProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "imap" && value["status"] == "* OK"
		}},
		{name: "vnc", payload: []byte("RFB 003.008\n"), contentType: "text/plain", protocol: vncprobe.Name, target: &vncProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "vnc" && value["protocol_version"] == "003.008"
		}},
		{name: "nats", payload: []byte("INFO {\"version\":\"2.10.18\"}\r\n"), contentType: "text/plain", protocol: natsprobe.Name, target: &natsProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "nats" && value["server_version"] == "2.10.18"
		}},
		{name: "rdp", payload: rdpConfirm(), contentType: "application/octet-stream", protocol: rdpprobe.Name, target: &rdpProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "rdp" && value["negotiation"] == "response" && value["selected_protocol"] == 1
		}},
		{name: "amqp", payload: []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}, contentType: "application/octet-stream", protocol: amqpprobe.Name, target: &amqpProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "amqp" && value["reply"] == "0-9-1"
		}},
		{name: "mqtt", payload: []byte{0x20, 0x02, 0x00, 0x05}, contentType: "application/octet-stream", protocol: mqttprobe.Name, target: &mqttProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "mqtt" && value["ack_code"] == 5
		}},
		{name: "kafka", payload: kafka, contentType: "application/octet-stream", protocol: kafkaprobe.Name, target: &kafkaProbeForPort, match: func(value map[string]any) bool {
			return value["protocol"] == "kafka" && value["error_code"] == 0
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			port := serveBytes(t, item.payload)
			pointProbe(t, item.target, port, item.protocol)
			now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
			svc, err := New(t.TempDir(), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
			run, err := svc.CreateScan(context.Background(), ScanInput{Name: item.name, Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID})
			if err != nil {
				t.Fatal(err)
			}
			finishRun(t, svc)
			var sawUnit bool
			_, units, _ := svc.tasks.Export()
			for _, unit := range units {
				if unit.ScanRunID == run.ID && unit.UnitType == "protocol_probe" && len(unit.RequiredCapabilities) == 1 && unit.RequiredCapabilities[0] == "protocol_"+item.protocol {
					sawUnit = true
				}
			}
			if !sawUnit {
				t.Fatalf("%s probe was not scheduled", item.protocol)
			}
			var sawService bool
			for _, hypothesis := range svc.Hypotheses() {
				if hypothesis.ServiceType == item.protocol && hypothesis.RawProductName == "" && hypothesis.RawVersion == "" && hypothesis.IdentityStatus == "unknown" && hypothesis.FingerprintPackVersion == rule.FingerprintVersion {
					sawService = true
				}
				if hypothesis.ServiceType != "" && hypothesis.ServiceType != item.protocol {
					t.Fatalf("unexpected service %s", hypothesis.ServiceType)
				}
			}
			if !sawService {
				t.Fatalf("hypotheses = %+v", svc.Hypotheses())
			}
			var sawEvidence bool
			for _, evidence := range svc.evidenceRows {
				if evidence.EvidenceType == "raw_response" && evidence.SourceModule == item.protocol+"probe" && evidence.ContentType == item.contentType && evidence.ContentEncoding == "identity" && evidence.Sensitivity == "internal" && evidence.IntegrityStatus == "verified" && evidence.StoredAt != nil {
					sawEvidence = true
				}
			}
			if !sawEvidence {
				t.Fatalf("evidence = %+v", svc.evidenceRows)
			}
			for _, observation := range svc.Observations(run.ID) {
				if observation.Type == "protocol_response" && item.match(observation.Value) {
					return
				}
			}
			t.Fatalf("observations = %+v", svc.Observations(run.ID))
		})
	}
}

func TestTelnetPortHintDoesNotOverrideTheResponse(t *testing.T) {
	port := serveBytes(t, []byte("HTTP/1.0 200 OK\r\n\r\n"))
	pointProbe(t, &telnetProbeForPort, port, telnetprobe.Name)
	now := time.Date(2026, 11, 5, 10, 5, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveTCPGrant(t, svc, "127.0.0.1", port, now)
	if _, err := svc.CreateScan(context.Background(), ScanInput{Name: "not-telnet", Target: "127.0.0.1", Type: "ip", Ports: []int{port}, GrantID: grantID}); err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "telnet" {
			t.Fatalf("http response became telnet: %+v", item)
		}
	}
}

func TestNTPProbeRecordsProtocolWithoutInventingProduct(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, udp.NTPPacketBytes)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil || n != udp.NTPPacketBytes || buf[0] != 0x23 || addr == nil {
			return
		}
		response := make([]byte, udp.NTPPacketBytes)
		response[0] = 0x24
		response[1] = 2
		_, _ = conn.WriteTo(response, addr)
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	pointProbe(t, &udpProbeForPort, port, udp.NTPName)
	now := time.Date(2026, 11, 5, 10, 10, 0, 0, time.UTC)
	svc, err := New(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	grantID := approveProbeGrant(t, svc, now, "127.0.0.1", port, port)
	run, err := svc.CreateScan(context.Background(), ScanInput{Name: "ntp", Target: "127.0.0.1", Type: "ip", Transport: "udp", Ports: []int{port}, GrantID: grantID})
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, svc)
	assertNoTCPUnits(t, svc, run.ID)
	if svc.accounts[run.ID].ExportUsage().Requests != 1 {
		t.Fatalf("requests = %d", svc.accounts[run.ID].ExportUsage().Requests)
	}
	var sawNTP bool
	for _, item := range svc.Observations(run.ID) {
		if item.Type == "protocol_response" && item.Value["protocol"] == "ntp" && item.Value["probe_version"] == udp.NTPVersion && item.Value["ntp_version"] == 4 && item.Value["stratum"] == 2 && item.Value["qname"] == nil && item.ResultStatus == "observed" {
			sawNTP = true
		}
	}
	if !sawNTP {
		t.Fatalf("observations = %+v", svc.Observations(run.ID))
	}
	var sawService bool
	for _, item := range svc.Hypotheses() {
		if item.ServiceType == "ntp" && item.RawProductName == "" && item.RawVersion == "" && item.IdentityStatus == "unknown" && item.FingerprintPackVersion == rule.FingerprintVersion {
			sawService = true
		}
	}
	if !sawService {
		t.Fatalf("hypotheses = %+v", svc.Hypotheses())
	}
	var sawEvidence bool
	for _, item := range svc.evidenceRows {
		if item.ContentType == "application/octet-stream" && item.SourceModule == "ntpprobe" && item.EvidenceType == "raw_response" {
			sawEvidence = true
		}
	}
	if !sawEvidence {
		t.Fatalf("evidence = %+v", svc.evidenceRows)
	}
}

func pointProbe(t *testing.T, target *func(int) string, port int, name string) {
	t.Helper()
	previous := *target
	*target = func(candidate int) string {
		if candidate == port {
			return name
		}
		return ""
	}
	t.Cleanup(func() { *target = previous })
}

func rdpConfirm() []byte {
	return []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
}

func kafkaFrame() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x0a,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}
