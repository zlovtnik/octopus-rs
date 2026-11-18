package log

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

type Logger struct {
	zl       zerolog.Logger
	redacted map[string]bool
	replacer *strings.Replacer
	mu       sync.RWMutex
}

func New() *Logger {
	redacted := map[string]bool{
		"cloudflared-tunnel-credentials":   true,
		"minio-credentials":                true,
		"observability-credentials":        true,
		"proxy-admin-key":                  true,
		"proxy-runtime-secrets":            true,
		"redis-runtime":                    true,
		"schema-migrator-backend":          true,
		"schema-migrator-bootstrap":        true,
		"schema-migrator-keycloak":         true,
		"ssl-proxy-identity-tls":           true,
		"postgres-atheros-search":          true,
		"postgres-keycloak":                true,
		"postgres-octopus":                 true,
		"postgres-octopus-metrics":         true,
		"octopus-metrics-store":            true,
		"postgres-schema-migrator":         true,
		"postgres-schema-owner":            true,
		"postgres-runtime-tls":             true,
		"pgbouncer-listener-tls":           true,
		"pgbouncer-runtime-users":          true,
		"wireguard-config":                 true,
		"ssl-proxy-prod-postgres-endpoint": true,
	}

	level, err := zerolog.ParseLevel(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	if err != nil || level == zerolog.NoLevel {
		level = zerolog.InfoLevel
	}
	return &Logger{
		zl:       zerolog.New(os.Stdout).Level(level).With().Timestamp().Logger(),
		redacted: redacted,
		replacer: newRedactor(redacted),
	}
}

func newRedactor(redacted map[string]bool) *strings.Replacer {
	names := make([]string, 0, len(redacted))
	for name := range redacted {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	pairs := make([]string, 0, len(names)*2)
	for _, name := range names {
		pairs = append(pairs, name, "[REDACTED]")
	}
	return strings.NewReplacer(pairs...)
}

func (l *Logger) redact(msg string) string {
	l.mu.RLock()
	replacer := l.replacer
	l.mu.RUnlock()
	return replacer.Replace(msg)
}

func (l *Logger) AddRedactedNames(names ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, name := range names {
		if name != "" {
			l.redacted[name] = true
		}
	}
	l.replacer = newRedactor(l.redacted)
}

func (l *Logger) Info(msg string, args ...interface{}) {
	l.write(l.zl.Info(), msg, args...)
}

func (l *Logger) Error(msg string, args ...interface{}) {
	l.write(l.zl.Error(), msg, args...)
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	l.write(l.zl.Warn(), msg, args...)
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	l.write(l.zl.Debug(), msg, args...)
}

func (l *Logger) write(event *zerolog.Event, msg string, args ...interface{}) {
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok || key == "" {
			key = fmt.Sprintf("field_%d", i/2)
		}
		key = l.redact(key)
		switch value := args[i+1].(type) {
		case bool:
			event.Bool(key, value)
		case int:
			event.Int(key, value)
		default:
			event.Str(key, l.redact(fmt.Sprint(value)))
		}
	}
	if len(args)%2 != 0 {
		event.Str("unpaired_field", l.redact(fmt.Sprint(args[len(args)-1])))
	}
	event.Msg(l.redact(msg))
}
