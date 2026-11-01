# Custom Parsers (YAML)

To onboard a log source that no built-in parser understands, add a YAML file. No Go code and no rebuild are needed, which matters on an air-gapped host where there is no toolchain.

```bash
drishti scan -parsers parsers/ logs/
```

Every `*.yaml` / `*.yml` file in the folder is one format. Custom formats are tried **before** the built-in parsers, in file-name order. Each definition file's path and SHA-256 are recorded in the audit trail (`config.definitions`), because they change what the analysis produces.

## Definition

```yaml
# parsers/zookeeper.yaml
name: zookeeper                      # required; becomes the entry's "parser" and drishti.parser in ECS
match: " - "                         # optional literal every line contains (cheap pre-filter)
pattern: '^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (?P<severity>[A-Z]+)\s+\[(?P<thread>.*):(?P<program>[\w$]+)@(?P<source_line>\d+)\] - (?P<message>.*)$'
time_layout: "2006-01-02 15:04:05,000"   # Go reference-time layout; empty = built-in layouts
rename: {client: src_ip}             # optional: group name → field name
facility: zookeeper                  # optional
```

The `pattern` is a [Go regular expression](https://pkg.go.dev/regexp/syntax) (RE2: linear time, so no catastrophic backtracking on hostile input). Its **named groups** become fields. These names have a meaning:

| Group | Becomes |
|---|---|
| `timestamp` | Entry time. Parsed with `time_layout`, else the built-in layouts (RFC 3339, `2006-01-02 15:04:05`, …). A layout without a numeric zone is read in `-tz` with DST handling, and a layout without a year gets the year inferred, exactly as for syslog. A value that doesn't parse is kept as `timestamp_unparsed`, and the entry is marked `Partial`. |
| `host` | Entry source (`host.name`), which cross-host correlation needs |
| `message` | Entry text (default: the whole line). Content rules and auth extraction read it. |
| `severity` | Level keyword (`INFO`, `WARN`, `ERROR`, `crit`, …) |
| `user`, `src_ip`, `src_port`, `program`, `pid` | The fields detection rules and the ECS mapping use. `rename` maps any group onto them. |

Every other group is kept under its own name (`drishti.fields.<name>` in ECS). If the message matches a known authentication pattern (sshd, PAM, …), auth fields are extracted from it as for any other source. Brute-force rules therefore work on a custom format without extra work.

## Validation

A folder is loaded completely or not at all, so a half-applied parser set can never silently change results. Loading fails when:

- a key is unknown (a misspelt `time_layot` is an error, not ignored),
- `name` is missing, duplicated, or the name of a built-in parser,
- `pattern` is missing, isn't a valid regular expression, or has no named groups,
- `time_layout` uses a zone abbreviation (`MST`), which Go cannot resolve reliably (unknown abbreviations become UTC). Use a numeric offset (`-0700`) or none,
- the folder contains no definitions.

## Shipped examples

| File | Format | Tested on |
|---|---|---|
| [`parsers/hdfs.yaml`](../parsers/hdfs.yaml) | Hadoop HDFS daemon log | First 200 lines of LogHub `HDFS_2k.log` (all `Clean`) |
| [`parsers/zookeeper.yaml`](../parsers/zookeeper.yaml) | Apache ZooKeeper log4j | First 200 lines of LogHub `Zookeeper_2k.log` (all `Clean`; thread names contain nested brackets) |

Without these definitions both files parse only as `BestEffort` raw text. See `TestIntegration_CustomYAMLParsers`.
