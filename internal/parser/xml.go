package parser

import (
	"drishti-nexus/internal/models"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// XMLParser parses Windows Event XML: one <Event> per record, single- or multi-line
// (wevtutil qe /f:xml, Get-WinEvent ... ToXml(), SIEM exports). The event is
// flattened to the key names of Windows JSON exports (EventID, Computer, Channel,
// and each EventData <Data Name="...">), so the JSON field extraction, Windows
// logon classification and ECS mapping apply unchanged.
//
// shortcut: several <Event> elements on one physical line (an Event Viewer
// "Save as XML" file is a single <Events> line, UTF-16) are not split; re-export one
// event per line (wevtutil qe /f:xml) until a source needs it.
type XMLParser struct{ json *JSONParser }

func NewXMLParser(ctx *Context) *XMLParser { return &XMLParser{json: NewJSONParser(ctx)} }

func (p *XMLParser) Name() string              { return "xml" }
func (p *XMLParser) CanParse(line string) bool { return isEventXMLStart(line) }

type winEventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       string `xml:"EventID"`
		Level         string `xml:"Level"`
		Task          string `xml:"Task"`
		Keywords      string `xml:"Keywords"`
		EventRecordID string `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
	Message string `xml:"RenderingInfo>Message"`
}

func (p *XMLParser) Parse(record string) (*models.LogEntry, error) {
	var ev winEventXML
	if err := xml.Unmarshal([]byte(record), &ev); err != nil {
		return nil, err
	}
	id, err := strconv.Atoi(strings.TrimSpace(ev.System.EventID))
	if err != nil {
		return nil, fmt.Errorf("event XML without a numeric EventID: %w", err)
	}

	data := map[string]interface{}{}
	var summary []string
	for i, d := range ev.Data {
		name := d.Name
		if name == "" {
			name = fmt.Sprintf("Data%d", i)
		}
		data[name] = d.Value
		summary = append(summary, name+"="+d.Value)
	}
	// System values are authoritative: set after EventData so a <Data Name="Channel"> cannot override them.
	sys := ev.System
	for k, v := range map[string]string{
		"Channel": sys.Channel, "Computer": sys.Computer, "ProviderName": sys.Provider.Name,
		"EventRecordID": sys.EventRecordID, "Task": sys.Task, "Keywords": sys.Keywords, "UserID": sys.Security.UserID,
	} {
		if v != "" {
			data[k] = v
		}
	}
	data["EventID"] = float64(id) // the JSON-number form Windows auth extraction expects

	entry := p.json.fromMap(data, record)
	if ts, ok := parseWithZoneFallback(p.json.ctx, sys.TimeCreated.SystemTime, data); ok {
		entry.Timestamp = ts
	}
	entry.Severity = windowsLevel(sys.Level)
	entry.Facility = sys.Channel
	entry.Message = strings.TrimSpace(ev.Message)
	if entry.Message == "" {
		// No rendered text in the export: list the event data so content rules still see command lines.
		entry.Message = fmt.Sprintf("%s %d: %s", sys.Provider.Name, id, strings.Join(summary, " "))
		data["message_synthesized"] = true
	}
	return entry, nil
}

// windowsLevel maps Windows event levels (0 LogAlways ... 5 Verbose) to severities.
func windowsLevel(level string) models.Severity {
	switch strings.TrimSpace(level) {
	case "1":
		return models.SeverityCritical
	case "2":
		return models.SeverityError
	case "3":
		return models.SeverityWarning
	case "5":
		return models.SeverityDebug
	}
	return models.SeverityInfo
}

// isEventXMLStart reports whether s opens a Windows <Event> element (not <Events>).
func isEventXMLStart(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "<Event>") || strings.HasPrefix(s, "<Event ")
}

// isXMLWrapper reports lines that carry no event: the XML declaration and the
// <Events> wrapper of a multi-event export.
func isXMLWrapper(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "<?xml") && strings.HasSuffix(s, "?>") || s == "<Events>" || s == "</Events>"
}
