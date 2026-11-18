package validate

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

const userlistToken = `"(?:[^"]|"")*"|[^"\s]+`

var userlistLine = regexp.MustCompile(`^(` + userlistToken + `)\s+(` + userlistToken + `)$`)

func userlistField(field string) string {
	if strings.HasPrefix(field, "\"") {
		return strings.ReplaceAll(field[1:len(field)-1], "\"\"", "\"")
	}
	return field
}

func validatePgBouncer(c *contract.Contract, data map[string]map[string][]byte) error {
	if err := validateServerTLS(
		c.Validation.Postgres.PgBouncerListenerTLSSecretName,
		c.Validation.Postgres.PgBouncerListenerTLSServerName,
		data,
	); err != nil {
		return fmt.Errorf("listener TLS: %w", err)
	}

	pgbouncerData, ok := data["pgbouncer-runtime-users"]
	if !ok {
		return fmt.Errorf("PgBouncer users secret not found")
	}

	userlist, ok := pgbouncerData["userlist.txt"]
	if !ok {
		return fmt.Errorf("PgBouncer users secret missing userlist.txt")
	}

	users := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(userlist)), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := userlistLine.FindStringSubmatch(line)
		if parts == nil {
			return fmt.Errorf("PgBouncer userlist line %d: invalid format", i+1)
		}
		username := userlistField(parts[1])
		password := userlistField(parts[2])
		if username == "" || password == "" {
			return fmt.Errorf("PgBouncer userlist line %d: empty username or password", i+1)
		}
		if _, duplicate := users[username]; duplicate {
			return fmt.Errorf("PgBouncer userlist contains duplicate account %s", username)
		}
		users[username] = password
	}

	requiredSecrets := []string{"postgres-atheros-search", "postgres-octopus", "postgres-octopus-metrics", "postgres-schema-migrator"}
	for _, secretName := range requiredSecrets {
		account, ok := c.Validation.Postgres.Accounts[secretName]
		if !ok || account == "" {
			return fmt.Errorf("contract does not declare required PgBouncer account for %s", secretName)
		}
		password, ok := users[account]
		if !ok {
			return fmt.Errorf("PgBouncer userlist missing required account %s", account)
		}
		credentials, ok := data[secretName]
		if !ok || len(credentials["password"]) == 0 {
			return fmt.Errorf("PgBouncer account secret %s missing non-empty password", secretName)
		}
		if password != string(credentials["password"]) {
			return fmt.Errorf("PgBouncer userlist password does not match account %s", account)
		}
	}

	return nil
}
