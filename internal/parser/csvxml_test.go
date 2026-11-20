package parser

import (
	"drishti-nexus/internal/models"
	"strings"
	"testing"
	"time"
)

func TestCSVHeader(t *testing.T) {
	for line, want := range map[string]bool{
		"LineId,Date,Day,Time,Component,Pid,Content,EventId,EventTemplate": true, // LogHub OpenSSH
		"LineId,Date,Time,Level,Component,Content,EventId,EventTemplate":   true, // LogHub Windows
		"Level,Date and Time,Source,Event ID,Task Category":                true, // Event Viewer export
		"CreationDate,UserIds,Operations,AuditData":                        true, // Microsoft 365 audit export
		"id,name,email": false, // no time column: data, not a log
		"Dec 10 06:55:46 LabSZ sshd[24200]: a, b, timestamp": false, // log text with commas
		"1,2016-09-28,04:30:30,Info":                         false, // a data row, not a header
		"time,host":                                          false, // too few columns to be sure
	} {
		if got := csvHeader(line) != nil; got != want {
			t.Errorf("csvHeader(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestCSV_QuotedMultilineRecord(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		"timestamp,host,message",
		`2025-03-10T10:00:00Z,web01,"first line`,
		`second line with ""quotes"", and a comma"`,
		`2025-03-10T10:00:01Z,web01,next`,
	)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (header consumed, quoted newline kept in one record)", len(entries))
	}
	e := entries[0]
	if e.Parser != "csv" || e.Source != "web01" || e.Message != "first line\nsecond line with \"quotes\", and a comma" ||
		e.Fields["line_count"] != 2 || !e.Timestamp.Equal(time.Date(2025, 3, 10, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("parser=%s source=%q msg=%q fields=%v", e.Parser, e.Source, e.Message, e.Fields)
	}
	if entries[1].Message != "next" || entries[1].LineNumber != 4 {
		t.Errorf("second record: %q at line %d", entries[1].Message, entries[1].LineNumber)
	}
}

func TestCSV_RowsAndFallbacks(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		"LineId,Date,Day,Time,Component,Pid,Content,EventId,EventTemplate",
		// LogHub OpenSSH row: year-less time over three columns, Pid feeds attempt de-duplication
		"24,Dec,10,07:07:38,LabSZ,24206,Failed password for invalid user test9 from 52.80.34.196 port 36060 ssh2,E10,Failed password for invalid user <*> from <*> port <*> ssh2",
		"oops,only three,columns", // wrong width: kept, best effort
	)
	e := entries[0]
	if e.Fields["pid"] != "24206" || e.Fields["auth_result"] != "failure" || e.Fields["src_ip"] != "52.80.34.196" ||
		e.Timestamp.Month() != time.December || e.Timestamp.Hour() != 7 || e.Severity < models.SeverityError {
		t.Errorf("row: ts=%s sev=%v fields=%v", e.Timestamp, e.Severity, e.Fields)
	}
	if entries[1].Parser != "generic" || entries[1].ParseQuality != models.QualityBestEffort {
		t.Errorf("malformed row: parser=%s quality=%s", entries[1].Parser, entries[1].ParseQuality)
	}
}

func TestCSV_HeaderOnlyOnFirstLine(t *testing.T) {
	entries := feed(t, newTestRegistry(),
		"Dec 10 06:55:46 LabSZ sshd[24200]: hello",
		"LineId,Date,Time,Level,Component,Content",
	)
	if len(entries) != 2 || entries[1].Parser == "csv" {
		t.Errorf("a header-like line after line 1 must not switch the file to CSV: %d entries", len(entries))
	}
}

const event4625 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12546</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2015-09-08T22:54:54.962511700Z" /><EventRecordID>229977</EventRecordID><Correlation /><Execution ProcessID="516" ThreadID="3240" /><Channel>Security</Channel><Computer>DC01.contoso.local</Computer><Security /></System><EventData><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="TargetUserName">Auditor</Data><Data Name="Status">0xc0000234</Data><Data Name="LogonType">2</Data><Data Name="IpAddress">127.0.0.1</Data><Data Name="IpPort">0</Data></EventData></Event>`

func TestXML_WindowsEvent(t *testing.T) {
	// Microsoft's documented 4625 event, one event per line as wevtutil writes it.
	e := parseOne(t, Options{}, event4625)
	if e.Parser != "xml" || e.Source != "DC01.contoso.local" || e.Facility != "Security" ||
		!e.Timestamp.Equal(time.Date(2015, 9, 8, 22, 54, 54, 962511700, time.UTC)) {
		t.Errorf("parser=%s source=%q facility=%q ts=%s", e.Parser, e.Source, e.Facility, e.Timestamp)
	}
	if e.Fields["EventID"] != float64(4625) || e.Fields["auth_result"] != "failure" || e.Fields["user"] != "Auditor" ||
		e.Fields["src_ip"] != "127.0.0.1" || e.Fields["LogonType"] != "2" || e.Fields["ProviderName"] != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("fields=%v", e.Fields)
	}
	if e.Fields["message_synthesized"] != true || !strings.Contains(e.Message, "TargetUserName=Auditor") {
		t.Errorf("message=%q", e.Message)
	}
}

func TestXML_MultilineWrappersAndIncomplete(t *testing.T) {
	pretty := strings.ReplaceAll(strings.ReplaceAll(event4625, "><", ">\n<"), "</Event>", "</Event>")
	lines := append([]string{`<?xml version="1.0" encoding="utf-8"?>`, "<Events>"}, strings.Split(pretty, "\n")...)
	lines = append(lines, "</Events>", `<Event xmlns="x"><System><EventID>4624</EventID>`) // cut off at EOF
	entries := feed(t, newTestRegistry(), lines...)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want the pretty event + the truncated one (wrappers skipped)", len(entries))
	}
	if entries[0].Parser != "xml" || entries[0].LineNumber != 3 || entries[0].Fields["user"] != "Auditor" {
		t.Errorf("pretty event: parser=%s line=%d fields=%v", entries[0].Parser, entries[0].LineNumber, entries[0].Fields)
	}
	if entries[1].Fields["record_incomplete"] != true || entries[1].ParseQuality == models.QualityClean {
		t.Errorf("truncated event: quality=%s fields=%v", entries[1].ParseQuality, entries[1].Fields)
	}
}

func TestXML_LevelsAndCommandLine(t *testing.T) {
	// Sysmon process creation (written here): no RenderingInfo, so the synthesized
	// message must carry CommandLine for the content rules.
	line := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Level>2</Level><TimeCreated SystemTime="2025-03-10T10:00:00Z"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS1</Computer></System><EventData><Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name="CommandLine">powershell.exe -enc SQBFAFgA</Data><Data>unnamed</Data></EventData></Event>`
	e := parseOne(t, Options{}, line)
	if e.Severity != models.SeverityError || !strings.Contains(e.Message, "CommandLine=powershell.exe -enc SQBFAFgA") ||
		e.Fields["Data2"] != "unnamed" || e.Fields["auth_result"] != "none" {
		t.Errorf("sev=%v msg=%q fields=%v", e.Severity, e.Message, e.Fields)
	}
	if e := parseOne(t, Options{}, `<Event><System><EventID>x</EventID></System></Event>`); e.Parser == "xml" {
		t.Error("an event without a numeric EventID must not parse as Windows XML")
	}
}
