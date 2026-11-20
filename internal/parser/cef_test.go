package parser

import (
	"drishti-nexus/internal/models"
	"testing"
	"time"
)

// Samples marked "logstash" are verbatim from the logstash-codec-cef test suite
// (spec/codecs/cef_spec.rb, Apache-2.0); "ArcSight spec" and "IBM" are the
// examples in the CEF and LEEF format specifications. The rest are written here
// to pin a specific behaviour.

func attrs(t *testing.T, e *models.LogEntry, key string) map[string]string {
	t.Helper()
	m, ok := e.Fields[key].(map[string]string)
	if !ok {
		t.Fatalf("Fields[%q] = %#v", key, e.Fields[key])
	}
	return m
}

func TestCEF_Header(t *testing.T) {
	// logstash: every header separator escaped
	e := parseOne(t, Options{}, `CEF:0|secu\|rity|threatmanager\||1.\|0|10\|0|tro\|jan successfully stopped|\|10|`)
	if e.Parser != "cef" || e.Fields["vendor"] != "secu|rity" || e.Fields["product"] != "threatmanager|" ||
		e.Fields["product_version"] != "1.|0" || e.Fields["event_class_id"] != "10|0" ||
		e.Message != "tro|jan successfully stopped" || e.Fields["vendor_severity"] != "|10" {
		t.Errorf("header escapes: parser=%s fields=%v msg=%q", e.Parser, e.Fields, e.Message)
	}

	// logstash
	e = parseOne(t, Options{}, `CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232`)
	if e.Severity != models.SeverityCritical || e.Fields["src_ip"] != "10.0.0.192" || e.Fields["dst_ip"] != "12.121.122.82" ||
		e.Fields["src_port"] != "1232" || e.ParseQuality != models.QualityClean {
		t.Errorf("basic: sev=%v quality=%s fields=%v", e.Severity, e.ParseQuality, e.Fields)
	}
}

func TestCEF_SyslogEnvelope(t *testing.T) {
	// ArcSight spec example
	e := parseOne(t, Options{}, `Sep 19 08:26:10 host CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`)
	if e.Parser != "cef" || e.Source != "host" || !e.Timestamp.Equal(time.Date(2024, 9, 19, 8, 26, 10, 0, time.UTC)) {
		t.Errorf("envelope: parser=%s source=%q ts=%s", e.Parser, e.Source, e.Timestamp)
	}
	if _, ok := e.Fields["program"]; ok {
		t.Errorf("the CEF marker must not become a syslog program: %v", e.Fields)
	}

	// Device time (rt, epoch ms) wins over the relay's envelope time.
	e = parseOne(t, Options{}, `<134>Sep 19 08:26:10 relay CEF:0|Acme|IDS|1|7|probe|3|rt=1500464384997 dvchost=sensor1`)
	if !e.Timestamp.Equal(time.UnixMilli(1500464384997).UTC()) || e.Source != "relay" {
		t.Errorf("rt precedence: ts=%s source=%q", e.Timestamp, e.Source)
	}
}

func TestCEF_Extension(t *testing.T) {
	tests := []struct {
		name, line string
		want       map[string]string
	}{
		{"escaped pipe (logstash)", `CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this\|has an escaped pipe`,
			map[string]string{"moo": "this|has an escaped pipe"}},
		{"raw pipe (logstash)", `CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this|has an pipe`,
			map[string]string{"moo": "this|has an pipe"}},
		{"equals in value (logstash)", `CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this =has = equals\=`,
			map[string]string{"moo": "this =has = equals="}},
		{"leading and double spaces (logstash)", `CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192  dst=12.121.122.82  spt=1232`,
			map[string]string{"src": "10.0.0.192", "dst": "12.121.122.82", "spt": "1232"}},
		{"values with spaces, URL with '=', empty value (logstash)",
			`CEF:0|FooBar|Web Gateway|1.2.3.45.67|200|Success|2|rt=Sep 07 2018 14:50:39 cat=Access Log dst=1.1.1.1 dhost=foo.example.com suser=redacted src=2.2.2.2 requestMethod=POST request='https://foo.example.com/bar/bingo/1' requestClientApplication='Foo-Bar/2018.1.7; Email:user@example.com; Guid:test=' cs1= cs1Label=Foo Bar`,
			map[string]string{"cat": "Access Log", "requestClientApplication": "'Foo-Bar/2018.1.7; Email:user@example.com; Guid:test='", "cs1": "", "cs1Label": "Foo Bar", "rt": "Sep 07 2018 14:50:39"}},
		{"dotted, bracketed and comma keys (logstash)",
			`CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 additional.dotfieldName=new_value ad.Authentification=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 ad.Error_,Code=3221225578 dst=12.121.122.82 ad.field[0]=field0 ad.name[1]=new_name`,
			map[string]string{"additional.dotfieldName": "new_value", "ad.Error_,Code": "3221225578", "ad.field[0]": "field0", "ad.name[1]": "new_name"}},
		{"escaped '=' in a long value (logstash)",
			`CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 cs4=401 random.user Admin 0 23041A10181C0000  23041810181C0000  /CN\=random.user/OU\=User Login End-Entity  /CN\=TEST/OU\=Login CA TEST 34 dst=12.121.122.82`,
			map[string]string{"cs4": "401 random.user Admin 0 23041A10181C0000  23041810181C0000  /CN=random.user/OU=User Login End-Entity  /CN=TEST/OU=Login CA TEST 34", "dst": "12.121.122.82"}},
	}
	for _, tt := range tests {
		e := parseOne(t, Options{}, tt.line)
		got := attrs(t, e, "cef")
		for k, v := range tt.want {
			if g, ok := got[k]; !ok || g != v {
				t.Errorf("%s: %s = %q (present=%v), want %q", tt.name, k, g, ok, v)
			}
		}
	}
}

func TestCEF_NormalizedFields(t *testing.T) {
	// logstash (interpolated rt/dtz removed)
	e := parseOne(t, Options{}, `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|Very-High| eventId=1 msg=Worm successfully stopped art=1500464384997 deviceSeverity=10 src=10.0.0.1 sourceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 spt=1232 dst=2.1.2.2 dvchost=client1`)
	if e.Severity != models.SeverityCritical || e.Source != "client1" || e.Message != "worm successfully stopped: Worm successfully stopped" ||
		attrs(t, e, "cef")["sourceZoneURI"] != "/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255" {
		t.Errorf("sev=%v source=%q msg=%q cef=%v", e.Severity, e.Source, e.Message, e.Fields["cef"])
	}

	// ArcSight date in rt, user from suser.
	e = parseOne(t, Options{}, `CEF:0|FooBar|Web Gateway|1.2.3.45.67|200|Success|2|rt=Sep 07 2018 14:50:39 cat=Access Log suser=redacted src=2.2.2.2`)
	if !e.Timestamp.Equal(time.Date(2018, 9, 7, 14, 50, 39, 0, time.UTC)) || e.Fields["user"] != "redacted" || e.Fields["auth_result"] != nil {
		t.Errorf("ts=%s fields=%v", e.Timestamp, e.Fields)
	}
}

func TestCEF_AuthEventsFeedDetection(t *testing.T) {
	e := parseOne(t, Options{}, `<134>Mar 10 10:14:01 vpn01 CEF:0|Acme|VPN|2.1|4625|User login failed|5|duser=deploy src=203.0.113.50 outcome=Failure`)
	if e.Fields["auth_result"] != "failure" || e.Fields["user"] != "deploy" || e.Fields["src_ip"] != "203.0.113.50" || e.Source != "vpn01" {
		t.Errorf("fields=%v source=%q", e.Fields, e.Source)
	}
}

func TestCEF_NotCEF(t *testing.T) {
	for _, line := range []string{
		`CEF:0|security|threatmanager|1.0|100|double backslash`, // logstash: too few header fields
		`CEF:7|a|b|c|d|e|f|x=1`,                                 // unknown version
		`Mar 10 10:14:01 host app: config key xCEF:0|a|b|c|d|e|f|g`,
	} {
		if e := parseOne(t, Options{}, line); e.Parser == "cef" {
			t.Errorf("%q parsed as CEF", line)
		}
	}
}

func TestLEEF(t *testing.T) {
	// IBM: LEEF 1.0 tab-separated, LEEF 2.0 with caret and hex delimiters
	for _, line := range []string{
		"LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|src=192.0.2.0\tdst=172.50.123.1\tsev=5\tcat=anomaly\tsrcPort=81\tdstPort=21\tusrName=joe.black",
		"LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=192.0.2.0^dst=172.50.123.1^sev=5^cat=anomaly^srcPort=81^dstPort=21^usrName=joe.black",
		"LEEF:2.0|Lancope|StealthWatch|1.0|41|x5E|src=192.0.2.0^dst=172.50.123.1^sev=5^cat=anomaly^srcPort=81^dstPort=21^usrName=joe.black",
		"LEEF:2.0|Lancope|StealthWatch|1.0|41|0x09|src=192.0.2.0\tdst=172.50.123.1\tsev=5\tcat=anomaly\tsrcPort=81\tdstPort=21\tusrName=joe.black",
	} {
		e := parseOne(t, Options{}, line)
		if e.Parser != "leef" || e.Fields["src_ip"] != "192.0.2.0" || e.Fields["dst_ip"] != "172.50.123.1" || e.Fields["src_port"] != "81" ||
			e.Fields["dst_port"] != "21" || e.Fields["user"] != "joe.black" || e.Severity != models.SeverityWarning || attrs(t, e, "leef")["cat"] != "anomaly" {
			t.Errorf("%q: parser=%s sev=%v fields=%v", line, e.Parser, e.Severity, e.Fields)
		}
	}

	// IBM: login events carry the outcome in cat.
	for line, want := range map[string]string{
		"LEEF:1.0|Microsoft|Exchange|2013|Login Event|cat=Failed":  "failure",
		"LEEF:1.0|Microsoft|Exchange|2013|Login Event|cat=Success": "success",
	} {
		if e := parseOne(t, Options{}, line); e.Fields["auth_result"] != want {
			t.Errorf("%q: auth_result=%v, want %s", line, e.Fields["auth_result"], want)
		}
	}

	// devTime (13-digit epoch) wins over the syslog envelope.
	e := parseOne(t, Options{}, "<13>Jan 18 11:07:53 gw01 LEEF:1.0|Acme|Gateway|1.0|Login Event|devTime=1700000000123\tusrName=alice\tcat=Success")
	if e.Source != "gw01" || !e.Timestamp.Equal(time.UnixMilli(1700000000123).UTC()) || e.Fields["user"] != "alice" {
		t.Errorf("envelope/devTime: source=%q ts=%s", e.Source, e.Timestamp)
	}

	// A devTime only its devTimeFormat explains is kept and flagged, never guessed.
	e = parseOne(t, Options{}, "LEEF:1.0|A|B|1|E|devTime=18/01/2024 11:07\tdevTimeFormat=dd/MM/yyyy HH:mm")
	if e.Fields["device_time_unparsed"] != "18/01/2024 11:07" || e.ParseQuality != models.QualityPartial {
		t.Errorf("unparsed devTime: quality=%s fields=%v", e.ParseQuality, e.Fields)
	}

	if e := parseOne(t, Options{}, "LEEF:2.0|A|B|1|E|zz|x=1"); e.Parser == "leef" {
		t.Error("invalid delimiter field accepted")
	}
}
