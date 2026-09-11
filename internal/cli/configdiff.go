package cli

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"aiproxy/internal/config"
)

// sensitiveConfigFields are config.Config field names whose actual
// value must never appear in a reload diff — mirrors the same "name
// exactly which fields carry a real credential, reviewed by name"
// discipline filterHeadersForScanning already applies to headers. A
// diff still reports that one of these changed, just never to or from
// what value. Every other field type either can't carry a secret on
// its own (bool/int/float64) or is itself a slice/map of structs
// (ProxyAPIKeys, Webhooks, CustomRules, ...), which formatConfigValue
// already renders as an entry count rather than raw content for every
// such field — so this list only needs the two plain-string fields
// that are themselves a bare credential.
var sensitiveConfigFields = map[string]bool{
	"ProxyAPIKey": true,
	"WebhookURL":  true,
}

// configFieldChange is one config.Config field that differs between an
// old and a new load, ready to render as "<json name>: <old> -> <new>".
type configFieldChange struct {
	JSONName string
	Old      string
	New      string
}

// diffConfig compares old and new field by field via reflection over
// config.Config's own exported fields — deliberately not a hand-written
// per-field comparison, so a newly added config field is automatically
// covered here without this function ever needing a matching update.
// Hand-maintained dual bookkeeping like that is exactly the kind of
// drift this project has already been bitten by once (the
// statsSnapshotJSON gap the cache-staleness release caught and fixed).
// Either argument may be nil — treated as every field at its zero
// value, the correct comparison base for a first-ever reload (nothing
// was loaded before) or a reload that finds no config file at all
// anymore (config.Load's own "missing file" case).
func diffConfig(old, newCfg *config.Config) []configFieldChange {
	oldV := reflect.ValueOf(configOrZero(old))
	newV := reflect.ValueOf(configOrZero(newCfg))
	t := oldV.Type()

	var changes []configFieldChange
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		oldField := oldV.Field(i)
		newField := newV.Field(i)
		if reflect.DeepEqual(oldField.Interface(), newField.Interface()) {
			continue
		}
		changes = append(changes, configFieldChange{
			JSONName: jsonFieldName(field),
			Old:      formatConfigValue(field.Name, oldField),
			New:      formatConfigValue(field.Name, newField),
		})
	}
	return changes
}

func configOrZero(cfg *config.Config) config.Config {
	if cfg == nil {
		return config.Config{}
	}
	return *cfg
}

// jsonFieldName returns field's own json struct tag name (the way it
// actually appears in aiproxy.json), falling back to the bare Go field
// name if it somehow has none — every config.Config field has one in
// practice, this is just a defensive fallback.
func jsonFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return field.Name
	}
	return name
}

// formatConfigValue renders one field's value for a diff line. name is
// sensitiveConfigFields-checked first, before ever looking at v's kind,
// so a secret field is redacted regardless of its underlying type.
// Every slice/map is rendered by entry count only, never its actual
// contents — including a []string field: a rule/target/route list can
// be long, and treating every slice uniformly (rather than special-
// casing "this one's safe to show in full") is a deliberately simpler,
// harder-to-get-wrong rule than trying to classify each one by hand.
func formatConfigValue(name string, v reflect.Value) string {
	if sensitiveConfigFields[name] {
		return "(hidden)"
	}
	switch v.Kind() {
	case reflect.Slice:
		return fmt.Sprintf("%d entries", v.Len())
	case reflect.Map:
		return fmt.Sprintf("%d entries", v.Len())
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'g', -1, 64)
	case reflect.String:
		s := v.String()
		if s == "" {
			return "(empty)"
		}
		return s
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}

// summarizeConfigDiff renders changes as one "; "-joined line, e.g.
// "max_requests_per_minute: 60 -> 100; cache_enabled: false -> true" —
// empty when there is nothing to report.
func summarizeConfigDiff(changes []configFieldChange) string {
	if len(changes) == 0 {
		return ""
	}
	parts := make([]string, len(changes))
	for i, c := range changes {
		parts[i] = fmt.Sprintf("%s: %s -> %s", c.JSONName, c.Old, c.New)
	}
	return strings.Join(parts, "; ")
}
