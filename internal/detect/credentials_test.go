package detect

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCredentialsFindsHandWrittenSecrets(t *testing.T) {
	for _, c := range []struct{ path, text string }{
		{"a.json", `{"aws":{"accessKeyId":"AKIAIOSFODNN7EXAMPLE"}}`},
		{"a.json", `{"legacy_servers":["db-prod-01.empresa.local:S3nh@Prod#2026"]}`},
		{"a.json", `{"legacy_servers":["://parceiro.com.br:FtpUsr$998877"]}`},
		{"a.json", `{"fallback_connection":"10.240.15.88:Admin#Backup2026"}`},
		{"a.json", `{"redis-cache.interno":"R3d1s_P@ssw0rd$99"}`},
		{"a.json", `{"10.240.15.88":"Admin#Backup2026"}`},
		{"a.json", "{\n  \"database_postgres\": \"P@ssw0rd_Pr0d_2026!\"\n}"},
		{"a.json", "{\n  \"smtp_email_service\": \"Smtp#Secr3t_9981\"\n}"},
		{"a.py", `DB_PASSWORD = "hunter2!Prod"`},
		{".env", "API_TOKEN=9f2c4e7a1b3d5f60\n"},
		{"a.json", `{"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`},
	} {
		if credentialMatch(c.path, c.text) == "" {
			t.Errorf("missed %s: %s", c.path, c.text)
		}
	}
}

func TestCredentialsIgnoresOrdinaryCode(t *testing.T) {
	for _, c := range []struct{ path, text string }{
		{"a.json", `{"slackWebhook":"https://slack.com/"}`},
		{"a.go", `token := parser.Next()`},
		{"a.rb", `database: "storage/development.sqlite3"`},
		{"a.js", `const server = "localhost:8080";`},
		{"a.json", `{"example.com": "Example Domain"}`},
		{"a.py", `password = os.environ["DB_PASSWORD"]`},
		{"a.yml", "password: ${DB_PASSWORD}\n"},
		{"a.rb", `version = "5.5.5-10.6.5-MariaDB-1:10.6.5+maria~focal"`},
		{"a.py", `relay = "127.0.0.1:{relay_ports[0]}"`},
		{"a.md", `Set ADMIN_PASSWORD = "<your password>" before running.`},
		{"a.py", `password_change_template = "custom_admin/password_change_form.html"`},
		{"a.py", `data = {"password1": "FORBIDDEN_VALUE2"}`},
		{"tox.ini", "postgres: -rtests/requirements/postgres.txt\n"},
		{"a.json", `{"Unexpected_token_1012": "予期しないトークンです。"}`},
		{"a.py", `FineTuningAPIKey.REPORTS: "reports:disabled-organizations"`},
	} {
		if match := credentialMatch(c.path, c.text); match != "" {
			t.Errorf("false positive %q in %s", match, c.text)
		}
	}
}

// FOCO_CREDENTIALS_CORPUS=dir1:dir2 lists every file the engine flags with
// the matching text, for reviewing false positives on real repositories.
func TestCredentialsCorpusReport(t *testing.T) {
	roots := os.Getenv("FOCO_CREDENTIALS_CORPUS")
	if roots == "" {
		t.Skip("set FOCO_CREDENTIALS_CORPUS to run")
	}
	files, hits := 0, 0
	for _, root := range filepath.SplitList(roots) {
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if entry.Name() == ".git" || entry.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil || len(data) > 1<<20 || bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
				return nil
			}
			files++
			if match := credentialMatch(path, string(data)); match != "" {
				hits++
				t.Logf("%s\t%s", path, strings.ReplaceAll(match, "\n", " "))
			}
			return nil
		})
	}
	t.Logf("files=%d flagged=%d", files, hits)
}
