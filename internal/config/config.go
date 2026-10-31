// Package config loads the detection configuration.
package config

import (
	"drishti-nexus/internal/models"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SearchPaths are tried in order when no -config flag is given: the repo layout,
// then a config.yaml next to the working directory (USB deployment beside the binary).
var SearchPaths = []string{
	filepath.Join("configs", "config.yaml"),
	"config.yaml",
}

// Load reads the config at path, or searches SearchPaths when path is "".
// It returns the path actually used ("" when falling back to built-in defaults).
func Load(path string) (*models.Config, string, error) {
	if path != "" {
		cfg, err := readFile(path)
		return cfg, path, err
	}
	for _, p := range SearchPaths {
		cfg, err := readFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return cfg, p, err
	}
	return Default(), "", nil
}

func readFile(path string) (*models.Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	cfg := Default()
	cfg.Rules = nil
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.MaxLogEntries <= 0 {
		cfg.MaxLogEntries = 100000
	}
	return cfg, nil
}

// Default is the built-in configuration used when no config file exists.
// Rule thresholds default inside the detection engine.
func Default() *models.Config {
	return &models.Config{
		NormalHours:   models.NormalHours{Start: 9, End: 17, Timezone: "UTC"},
		IncidentGap:   "30m",
		MaxLogEntries: 100000,
	}
}
