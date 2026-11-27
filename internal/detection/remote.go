package detection

import (
	"drishti-nexus/internal/models"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// RemoteServiceDetector catches PsExec-style lateral movement done with valid
// credentials (no brute force for the Lateral Movement rule to key on): on host B
// a service is installed (System 7045 / Security 4697) shortly after a network
// logon (4624, logon type 3) from a remote address. The source address is
// resolved to a host from the Sysmon network connections that host initiated;
// when that mapping is seen only after the alert (log order), the alert is
// completed and linked then. A resolved source joins the source host's incident.
type RemoteServiceDetector struct {
	engine *Engine
}

func (d *RemoteServiceDetector) Name() string { return RuleRemoteService }

// netLogon is a network logon on a host, kept for the rule window.
type netLogon struct {
	At   time.Time `json:"at"`
	IP   string    `json:"ip"`
	User string    `json:"user"`
	ID   string    `json:"id"` // evidence entry ID
}

func (d *RemoteServiceDetector) Analyze(ev *Event) *Finding {
	e, entry := d.engine, ev.Entry
	window := e.setting(RuleRemoteService).Window
	switch windowsEventID(entry) {
	case 3: // Sysmon network connection: an initiated one names this host's own address
		if fieldText(entry, "Initiated") == "true" {
			e.learnHostIP(fieldText(entry, "SourceIp"), ev.Host)
		}
	case 4624:
		if ip := fieldText(entry, "IpAddress"); fieldText(entry, "LogonType") == "3" && remoteIP(ip) {
			logons := append(e.state.NetLogons[ev.Host], netLogon{At: entry.Timestamp, IP: ip, User: fieldText(entry, "TargetUserName"), ID: entry.ID})
			i := 0
			for i < len(logons) && entry.Timestamp.Sub(logons[i].At) > window {
				i++
			}
			e.state.NetLogons[ev.Host] = logons[i:]
		}
	case 7045, 4697:
		return d.serviceAfterLogon(ev, window)
	}
	return nil
}

func (d *RemoteServiceDetector) serviceAfterLogon(ev *Event, window time.Duration) *Finding {
	e, entry := d.engine, ev.Entry
	var logon *netLogon
	for i := range e.state.NetLogons[ev.Host] {
		l := &e.state.NetLogons[ev.Host][i]
		if dt := entry.Timestamp.Sub(l.At); dt >= 0 && dt <= window {
			logon = l // latest qualifying logon wins
		}
	}
	if logon == nil {
		return nil
	}
	service := fieldText(entry, "ServiceName")
	f := &Finding{
		AggKey:  ev.Host + "|" + logon.IP + "|" + service,
		CorrKey: ev.Key,
		Description: fmt.Sprintf("Remote service execution on %s: service %q installed %s after a network logon by %s from %s",
			ev.Host, service, entry.Timestamp.Sub(logon.At), logon.User, logon.IP),
		Details: map[string]interface{}{
			"destination_host": ev.Host,
			"source_ip":        logon.IP,
			"user":             logon.User,
			"service":          service,
			"delay":            entry.Timestamp.Sub(logon.At).String(),
			"window":           window.String(),
		},
		Evidence:  []string{logon.ID},
		FirstSeen: logon.At,
	}
	if src := e.state.HostIPs[logon.IP]; src != "" && src != ev.Host {
		f.Details["source_host"] = src
		f.Description += " (" + src + ")"
		if a := e.latestAlertOn(src); a != nil {
			f.LinkTo = a.ID
		}
	}
	return f
}

// learnHostIP records that ip belongs to host, and completes remote-service alerts
// that were raised before the mapping was known.
func (e *Engine) learnHostIP(ip, host string) {
	if !remoteIP(ip) || e.state.HostIPs[ip] == host {
		return
	}
	e.state.HostIPs[ip] = host
	for _, a := range e.alerts {
		if a.RuleName != RuleRemoteService || a.Details["source_ip"] != ip || a.Details["source_host"] != nil || a.Details["destination_host"] == host {
			continue
		}
		a.Details["source_host"] = host
		a.Description += " (" + host + ", identified from its own network connections)"
		if src := e.latestAlertOn(host); src != nil {
			e.link(src, a)
		} else {
			e.storage.UpdateAlert(a)
		}
	}
}

// latestAlertOn returns the most recently active open alert raised for host.
func (e *Engine) latestAlertOn(host string) *models.Alert {
	var best *models.Alert
	for _, a := range e.alerts {
		k := a.CorrelationKey
		if (k == "host="+host || strings.HasPrefix(k, "host="+host+"|")) && (best == nil || a.LastSeen.After(best.LastSeen)) {
			best = a
		}
	}
	return best
}

// windowsEventID returns the entry's EventID (JSON number or string), or 0.
func windowsEventID(entry *models.LogEntry) int {
	switch v := entry.Fields["EventID"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

// fieldText returns a field as text whatever its JSON type ("" when absent).
func fieldText(entry *models.LogEntry, key string) string {
	if v, ok := entry.Fields[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// remoteIP reports a real peer address: not "-", loopback or unspecified.
func remoteIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}
