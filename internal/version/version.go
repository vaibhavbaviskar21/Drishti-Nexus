// Package version holds build identification, overridable at link time:
//
//	go build -ldflags "-X drishti-nexus/internal/version.Version=1.1.0" ./cmd/drishti
package version

// Version of Drishti Nexus recorded in audit trails and reports.
var Version = "1.1.0-dev"
