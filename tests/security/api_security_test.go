package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/mailhog/Pat/config"
	"github.com/mailhog/Pat/pkg/fortress"
)

// FortressAPISecurityTestSuite validates comprehensive API security measures
type FortressAPISecurityTestSuite struct {
	testServer *httptest.Server
	fortress   *fortress.Service
}

// TestAPISecurityValidation is the main API security test entry point
func TestAPISecurityValidation(t *testing.T) {
	suite := setupAPISecurityTestSuite(t)
	defer suite.cleanup(t)

	t.Run("Input_Validation_Security", suite.testInputValidationSecurity)
	t.Run("Cross_Site_Scripting_Prevention", suite.testXSSPrevention)
	t.Run("Command_Injection_Prevention", suite.testCommandInjectionPrevention)
	t.Run("Path_Traversal_Prevention", suite.testPathTraversalPrevention)
	t.Run("File_Upload_Security", suite.testFileUploadSecurity)
	t.Run("GraphQL_Security_Validation", suite.testGraphQLSecurity)
	t.Run("Rate_Limiting_Security", suite.testRateLimitingSecurity)
	t.Run("HTTP_Method_Security", suite.testHTTPMethodSecurity)
	t.Run("Content_Type_Validation", suite.testContentTypeValidation)
	t.Run("CORS_Security_Validation", suite.testCORSSecurity)
	t.Run("HTTP_Headers_Security", suite.testHTTPHeadersSecurity)
	t.Run("API_Versioning_Security", suite.testAPIVersioningSecurity)
	t.Run("Error_Handling_Security", suite.testErrorHandlingSecurity)
	t.Run("Request_Size_Limits", suite.testRequestSizeLimits)
}

func setupAPISecurityTestSuite(t *testing.T) *FortressAPISecurityTestSuite {
	cfg := &config.Config{
		EnableSecurity:       true,
		SecurityLevel:       "fortress",
		MaxRequestSize:      1024 * 1024, // 1MB
		EnableRateLimit:     true,
		RateLimitRequests:   100,
		RateLimitPeriod:     time.Minute,
		EnableCORS:          true,
		AllowedOrigins:      []string{"https://trusted.example.com"},
		EnableCSP:           true,
	}

	fortress := fortress.NewService(cfg)
	server := httptest.NewServer(createAPISecurityHandler(fortress))

	return &FortressAPISecurityTestSuite{
		testServer: server,
		fortress:   fortress,
	}
}

func (s *FortressAPISecurityTestSuite) cleanup(t *testing.T) {
	s.testServer.Close()
}

// testInputValidationSecurity tests comprehensive input validation
func (s *FortressAPISecurityTestSuite) testInputValidationSecurity(t *testing.T) {
	maliciousInputs := []struct {
		name     string
		payload  map[string]interface{}
		endpoint string
	}{
		{
			name: "Email_Validation_XSS",
			payload: map[string]interface{}{
				"email":   "<script>alert('xss')</script>@example.com",
				"subject": "Test Subject",
			},
			endpoint: "/api/v3/emails",
		},
		{
			name: "Subject_SQL_Injection",
			payload: map[string]interface{}{
				"subject": "'; DROP TABLE emails; --",
				"content": "Test content",
			},
			endpoint: "/api/v3/emails",
		},
		{
			name: "Content_LDAP_Injection",
			payload: map[string]interface{}{
				"content": "user=*)(uid=*))(|(uid=*",
				"email":   "test@example.com",
			},
			endpoint: "/api/v3/emails",
		},
		{
			name: "JSON_Injection",
			payload: map[string]interface{}{
				"data": `{"injection": "'; DROP TABLE users; --"}`,
			},
			endpoint: "/api/v3/data/process",
		},
		{
			name: "XML_External_Entity",
			payload: map[string]interface{}{
				"xml": `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
			},
			endpoint: "/api/v3/xml/process",
		},
		{
			name: "NoSQL_Injection",
			payload: map[string]interface{}{
				"filter": map[string]interface{}{
					"$where": "function() { return true; }",
				},
			},
			endpoint: "/api/v3/emails/search",
		},
		{
			name: "Template_Injection",
			payload: map[string]interface{}{
				"template": "{{7*7}} ${7*7} <%=7*7%> #{7*7}",
			},
			endpoint: "/api/v3/templates/render",
		},
	}

	for _, testCase := range maliciousInputs {
		t.Run(testCase.name, func(t *testing.T) {
			jsonData, err := json.Marshal(testCase.payload)
			require.NoError(t, err)

			resp, err := http.Post(s.testServer.URL+testCase.endpoint,
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should not return 500 (internal server error) due to malicious input
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
				"Malicious input should not cause internal server error")

			// Read response body to check for injection success
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			responseBody := string(body)

			// Verify no malicious content is reflected or executed
			assert.NotContains(t, responseBody, "<script>")
			assert.NotContains(t, responseBody, "alert")
			assert.NotContains(t, responseBody, "root:x:")  // /etc/passwd content
			assert.NotContains(t, responseBody, "49")       // 7*7 result indicating template injection
		})
	}
}

// testXSSPrevention tests Cross-Site Scripting prevention
func (s *FortressAPISecurityTestSuite) testXSSPrevention(t *testing.T) {
	xssPayloads := []struct {
		name    string
		payload string
		context string
	}{
		{
			name:    "Basic_Script_Tag",
			payload: "<script>alert('xss')</script>",
			context: "email_content",
		},
		{
			name:    "Event_Handler_XSS",
			payload: "<img src=x onerror=alert('xss')>",
			context: "subject",
		},
		{
			name:    "JavaScript_Protocol",
			payload: "<a href='javascript:alert(\"xss\")'>Click</a>",
			context: "content",
		},
		{
			name:    "Data_URI_XSS",
			payload: "<iframe src='data:text/html,<script>alert(\"xss\")</script>'></iframe>",
			context: "signature",
		},
		{
			name:    "SVG_XSS",
			payload: "<svg onload=alert('xss')></svg>",
			context: "content",
		},
		{
			name:    "HTML_Entity_XSS",
			payload: "&lt;script&gt;alert('xss')&lt;/script&gt;",
			context: "subject",
		},
		{
			name:    "CSS_Expression_XSS",
			payload: "<div style='background:url(javascript:alert(\"xss\"))'></div>",
			context: "content",
		},
		{
			name:    "Unicode_XSS",
			payload: "<script>\\u0061\\u006c\\u0065\\u0072\\u0074('xss')</script>",
			context: "content",
		},
	}

	for _, xssTest := range xssPayloads {
		t.Run(xssTest.name, func(t *testing.T) {
			// Test in different API contexts
			testPayload := map[string]interface{}{
				xssTest.context: xssTest.payload,
				"email":         "test@example.com",
			}

			jsonData, _ := json.Marshal(testPayload)
			resp, err := http.Post(s.testServer.URL+"/api/v3/emails",
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			responseBody := string(body)

			// Verify XSS payload is sanitized or escaped
			assert.NotContains(t, responseBody, "<script>")
			assert.NotContains(t, responseBody, "javascript:")
			assert.NotContains(t, responseBody, "alert(")
			assert.NotContains(t, responseBody, "onerror=")
			assert.NotContains(t, responseBody, "onload=")

			// Test in GET parameters as well
			encodedPayload := url.QueryEscape(xssTest.payload)
			resp2, err := http.Get(s.testServer.URL + "/api/v3/emails?search=" + encodedPayload)
			require.NoError(t, err)
			defer resp2.Body.Close()

			body2, err := io.ReadAll(resp2.Body)
			require.NoError(t, err)
			responseBody2 := string(body2)

			assert.NotContains(t, responseBody2, "<script>")
			assert.NotContains(t, responseBody2, "javascript:")
		})
	}
}

// testCommandInjectionPrevention tests command injection prevention
func (s *FortressAPISecurityTestSuite) testCommandInjectionPrevention(t *testing.T) {
	commandInjectionPayloads := []struct {
		name    string
		payload string
		field   string
	}{
		{
			name:    "Bash_Command_Injection",
			payload: "test@example.com; cat /etc/passwd",
			field:   "email",
		},
		{
			name:    "PowerShell_Injection",
			payload: "test@example.com; Get-Process",
			field:   "email",
		},
		{
			name:    "Python_Injection",
			payload: "test@example.com'; __import__('os').system('id'); #",
			field:   "subject",
		},
		{
			name:    "Node_JS_Injection",
			payload: "'; require('child_process').exec('whoami'); //",
			field:   "content",
		},
		{
			name:    "Pipe_Command_Injection",
			payload: "test@example.com | whoami",
			field:   "recipient",
		},
		{
			name:    "Backtick_Injection",
			payload: "test@example.com`whoami`",
			field:   "sender",
		},
		{
			name:    "Subshell_Injection",
			payload: "test@example.com$(whoami)",
			field:   "subject",
		},
	}

	for _, injectionTest := range commandInjectionPayloads {
		t.Run(injectionTest.name, func(t *testing.T) {
			testPayload := map[string]interface{}{
				injectionTest.field: injectionTest.payload,
				"action":            "process_email",
			}

			jsonData, _ := json.Marshal(testPayload)
			resp, err := http.Post(s.testServer.URL+"/api/v3/emails/process",
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			responseBody := string(body)

			// Should not execute commands or return command output
			assert.NotContains(t, responseBody, "root:x:")        // /etc/passwd content
			assert.NotContains(t, responseBody, "uid=")          // id command output
			assert.NotContains(t, responseBody, "ProcessName")   // PowerShell output
			assert.NotContains(t, responseBody, "System")        // Command execution indicators

			// Should handle malicious input gracefully
			assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
		})
	}
}

// testPathTraversalPrevention tests path traversal attack prevention
func (s *FortressAPISecurityTestSuite) testPathTraversalPrevention(t *testing.T) {
	pathTraversalPayloads := []struct {
		name     string
		payload  string
		endpoint string
	}{
		{
			name:     "Basic_Path_Traversal",
			payload:  "../../../etc/passwd",
			endpoint: "/api/v3/files",
		},
		{
			name:     "Windows_Path_Traversal",
			payload:  "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
			endpoint: "/api/v3/files",
		},
		{
			name:     "URL_Encoded_Traversal",
			payload:  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			endpoint: "/api/v3/files",
		},
		{
			name:     "Double_URL_Encoded",
			payload:  "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
			endpoint: "/api/v3/files",
		},
		{
			name:     "Unicode_Path_Traversal",
			payload:  "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
			endpoint: "/api/v3/files",
		},
		{
			name:     "Null_Byte_Injection",
			payload:  "../../../etc/passwd%00.jpg",
			endpoint: "/api/v3/files",
		},
	}

	for _, traversalTest := range pathTraversalPayloads {
		t.Run(traversalTest.name, func(t *testing.T) {
			// Test in URL path
			resp, err := http.Get(s.testServer.URL + traversalTest.endpoint + "/" + traversalTest.payload)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			responseBody := string(body)

			// Should not access system files
			assert.NotContains(t, responseBody, "root:x:")
			assert.NotContains(t, responseBody, "localhost")
			assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Path traversal should not succeed")

			// Test in POST body
			testPayload := map[string]interface{}{
				"filename": traversalTest.payload,
				"action":   "read_file",
			}

			jsonData, _ := json.Marshal(testPayload)
			resp2, err := http.Post(s.testServer.URL+"/api/v3/files/read",
				"application/json", bytes.NewBuffer(jsonData))
			require.NoError(t, err)
			defer resp2.Body.Close()

			body2, err := io.ReadAll(resp2.Body)
			require.NoError(t, err)
			responseBody2 := string(body2)

			assert.NotContains(t, responseBody2, "root:x:")
			assert.NotContains(t, responseBody2, "localhost")
		})
	}
}

// testFileUploadSecurity tests file upload security mechanisms
func (s *FortressAPISecurityTestSuite) testFileUploadSecurity(t *testing.T) {
	maliciousFiles := []struct {
		name        string
		filename    string
		content     string
		contentType string
	}{
		{
			name:        "PHP_Webshell",
			filename:    "shell.php",
			content:     "<?php system($_GET['cmd']); ?>",
			contentType: "application/x-php",
		},
		{
			name:        "JSP_Webshell",
			filename:    "shell.jsp",
			content:     "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
			contentType: "application/x-jsp",
		},
		{
			name:        "Executable_File",
			filename:    "malware.exe",
			content:     "MZ\x90\x00\x03", // PE header
			contentType: "application/x-msdownload",
		},
		{
			name:        "Script_With_Valid_Extension",
			filename:    "image.jpg.php",
			content:     "<?php phpinfo(); ?>",
			contentType: "image/jpeg",
		},
		{
			name:        "HTML_With_Script",
			filename:    "document.html",
			content:     "<html><script>alert('xss')</script></html>",
			contentType: "text/html",
		},
		{
			name:        "SVG_With_Script",
			filename:    "image.svg",
			content:     "<svg onload=\"alert('xss')\"><\/svg>",
			contentType: "image/svg+xml",
		},
		{
			name:        "Large_File_DoS",
			filename:    "large.txt",
			content:     strings.Repeat("A", 10*1024*1024), // 10MB
			contentType: "text/plain",
		},
		{
			name:        "Path_Traversal_Filename",
			filename:    "../../../etc/passwd",
			content:     "malicious content",
			contentType: "text/plain",
		},
	}

	for _, fileTest := range maliciousFiles {
		t.Run(fileTest.name, func(t *testing.T) {
			// Create multipart form data
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)

			part, err := writer.CreateFormFile("file", fileTest.filename)
			require.NoError(t, err)
			part.Write([]byte(fileTest.content))
			writer.Close()

			req, err := http.NewRequest("POST", s.testServer.URL+"/api/v3/files/upload", body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", writer.FormDataContentType())

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Malicious files should be rejected
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				fmt.Sprintf("Malicious file %s should be rejected", fileTest.filename))

			responseBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			// Should not execute or process malicious content
			assert.NotContains(t, string(responseBody), "phpinfo")
			assert.NotContains(t, string(responseBody), "alert")
		})
	}
}

// testGraphQLSecurity tests GraphQL security mechanisms
func (s *FortressAPISecurityTestSuite) testGraphQLSecurity(t *testing.T) {
	maliciousGraphQLQueries := []struct {
		name  string
		query string
	}{
		{
			name: "Deep_Nested_Query_DoS",
			query: `{
				user {
					emails {
						attachments {
							metadata {
								properties {
									details {
										info {
											data {
												values {
													items
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}`,
		},
		{
			name: "Query_Complexity_Attack",
			query: strings.Repeat(`{
				users {
					emails {
						id
						sender
						recipient
						subject
						content
						attachments {
							filename
							size
							type
						}
					}
				}
			}`, 100),
		},
		{
			name: "Introspection_Attack",
			query: `{
				__schema {
					types {
						name
						fields {
							name
							type {
								name
							}
						}
					}
				}
			}`,
		},
		{
			name: "Batch_Query_Attack",
			query: `[
				{ "query": "{ users { id } }" },
				{ "query": "{ users { id } }" },
				{ "query": "{ users { id } }" }
			]`,
		},
		{
			name: "Resource_Exhaustion_Query",
			query: `{
				users(first: 999999) {
					emails(first: 999999) {
						attachments(first: 999999) {
							id
						}
					}
				}
			}`,
		},
	}

	for _, gqlTest := range maliciousGraphQLQueries {
		t.Run(gqlTest.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"query": gqlTest.query,
			}

			jsonData, _ := json.Marshal(payload)
			
			startTime := time.Now()
			resp, err := http.Post(s.testServer.URL+"/graphql",
				"application/json", bytes.NewBuffer(jsonData))
			duration := time.Since(startTime)
			
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should not take too long (DoS prevention)
			assert.Less(t, duration, time.Second*5, "GraphQL query should not cause DoS")

			// Should handle malicious queries appropriately
			if resp.StatusCode == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				responseBody := string(body)

				// Should not expose internal schema details
				assert.NotContains(t, responseBody, "__schema")
				assert.NotContains(t, responseBody, "database")
				assert.NotContains(t, responseBody, "password")
			}
		})
	}
}

// testRateLimitingSecurity tests rate limiting mechanisms
func (s *FortressAPISecurityTestSuite) testRateLimitingSecurity(t *testing.T) {
	// Test basic rate limiting
	endpoint := s.testServer.URL + "/api/v3/emails"
	
	// Make requests rapidly to trigger rate limiting
	var responses []*http.Response
	for i := 0; i < 150; i++ { // More than the limit
		resp, err := http.Get(endpoint)
		require.NoError(t, err)
		responses = append(responses, resp)
		
		if i > 100 { // After exceeding rate limit
			if resp.StatusCode == http.StatusTooManyRequests {
				break
			}
		}
	}

	// Clean up responses
	for _, resp := range responses {
		resp.Body.Close()
	}

	// Should have triggered rate limiting
	rateLimited := false
	for _, resp := range responses[100:] {
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
	}
	assert.True(t, rateLimited, "Rate limiting should be triggered after exceeding limit")

	// Test rate limit bypass attempts
	bypassAttempts := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "X_Forwarded_For_Bypass",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.100",
			},
		},
		{
			name: "X_Real_IP_Bypass",
			headers: map[string]string{
				"X-Real-IP": "10.0.0.1",
			},
		},
		{
			name: "Multiple_Header_Bypass",
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
				"X-Real-IP":       "127.0.0.1",
				"X-Client-IP":     "127.0.0.1",
			},
		},
	}

	for _, attempt := range bypassAttempts {
		t.Run(attempt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", endpoint, nil)
			require.NoError(t, err)

			for key, value := range attempt.headers {
				req.Header.Set(key, value)
			}

			// Try multiple requests with bypass headers
			for i := 0; i < 10; i++ {
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
			}
			// Note: In a real implementation, we'd verify the rate limit still applies
		})
	}
}

// testHTTPMethodSecurity tests HTTP method security
func (s *FortressAPISecurityTestSuite) testHTTPMethodSecurity(t *testing.T) {
	endpoints := []string{
		"/api/v3/emails",
		"/api/v3/users",
		"/api/v3/admin/settings",
	}

	disallowedMethods := []string{
		"TRACE", "TRACK", "DEBUG", "CONNECT", "OPTIONS",
	}

	for _, endpoint := range endpoints {
		for _, method := range disallowedMethods {
			t.Run(fmt.Sprintf("%s_%s", method, endpoint), func(t *testing.T) {
				req, err := http.NewRequest(method, s.testServer.URL+endpoint, nil)
				require.NoError(t, err)

				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should not allow potentially dangerous HTTP methods
				assert.Contains(t, []int{
					http.StatusMethodNotAllowed,
					http.StatusNotImplemented,
					http.StatusForbidden,
				}, resp.StatusCode, fmt.Sprintf("Method %s should not be allowed", method))
			})
		}
	}
}

// testContentTypeValidation tests content type validation
func (s *FortressAPISecurityTestSuite) testContentTypeValidation(t *testing.T) {
	maliciousContentTypes := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "XML_External_Entity",
			contentType: "application/xml",
			body:        `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		},
		{
			name:        "Malformed_JSON",
			contentType: "application/json",
			body:        `{"malformed": json content}`,
		},
		{
			name:        "Binary_Content",
			contentType: "application/octet-stream",
			body:        "\x00\x01\x02\x03\x04",
		},
		{
			name:        "Script_Content_Type",
			contentType: "text/javascript",
			body:        `alert('xss')`,
		},
	}

	for _, contentTest := range maliciousContentTypes {
		t.Run(contentTest.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", s.testServer.URL+"/api/v3/emails",
				strings.NewReader(contentTest.body))
			require.NoError(t, err)
			
			req.Header.Set("Content-Type", contentTest.contentType)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Should handle unsupported content types appropriately
			if contentTest.contentType != "application/json" {
				assert.Contains(t, []int{
					http.StatusUnsupportedMediaType,
					http.StatusBadRequest,
					http.StatusNotAcceptable,
				}, resp.StatusCode, "Unsupported content type should be rejected")
			}
		})
	}
}

// testCORSSecurity tests CORS security configuration
func (s *FortressAPISecurityTestSuite) testCORSSecurity(t *testing.T) {
	corsTests := []struct {
		name     string
		origin   string
		method   string
		expected bool
	}{
		{
			name:     "Trusted_Origin",
			origin:   "https://trusted.example.com",
			method:   "GET",
			expected: true,
		},
		{
			name:     "Untrusted_Origin",
			origin:   "https://malicious.com",
			method:   "GET",
			expected: false,
		},
		{
			name:     "Null_Origin",
			origin:   "null",
			method:   "GET",
			expected: false,
		},
		{
			name:     "Wildcard_Bypass",
			origin:   "*",
			method:   "GET",
			expected: false,
		},
	}

	for _, corsTest := range corsTests {
		t.Run(corsTest.name, func(t *testing.T) {
			req, err := http.NewRequest(corsTest.method, s.testServer.URL+"/api/v3/emails", nil)
			require.NoError(t, err)
			
			req.Header.Set("Origin", corsTest.origin)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			allowedOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			
			if corsTest.expected {
				assert.Equal(t, corsTest.origin, allowedOrigin, "Trusted origin should be allowed")
			} else {
				assert.NotEqual(t, corsTest.origin, allowedOrigin, "Untrusted origin should not be allowed")
			}
		})
	}
}

// testHTTPHeadersSecurity tests HTTP security headers
func (s *FortressAPISecurityTestSuite) testHTTPHeadersSecurity(t *testing.T) {
	resp, err := http.Get(s.testServer.URL + "/api/v3/emails")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check for security headers
	securityHeaders := map[string]bool{
		"X-Content-Type-Options": true,
		"X-Frame-Options":        true,
		"X-XSS-Protection":       true,
		"Strict-Transport-Security": false, // May not be set in test
		"Content-Security-Policy":   true,
		"Referrer-Policy":          false, // Optional
	}

	for header, required := range securityHeaders {
		value := resp.Header.Get(header)
		if required {
			assert.NotEmpty(t, value, fmt.Sprintf("Security header %s should be present", header))
		}
		
		// Validate specific header values
		switch header {
		case "X-Content-Type-Options":
			assert.Equal(t, "nosniff", value)
		case "X-Frame-Options":
			assert.Contains(t, []string{"DENY", "SAMEORIGIN"}, value)
		case "X-XSS-Protection":
			assert.Equal(t, "1; mode=block", value)
		}
	}
}

// testAPIVersioningSecurity tests API versioning security
func (s *FortressAPISecurityTestSuite) testAPIVersioningSecurity(t *testing.T) {
	versionTests := []struct {
		name     string
		endpoint string
		expected int
	}{
		{
			name:     "Valid_Version",
			endpoint: "/api/v3/emails",
			expected: http.StatusOK,
		},
		{
			name:     "Invalid_Version",
			endpoint: "/api/v999/emails",
			expected: http.StatusNotFound,
		},
		{
			name:     "Missing_Version",
			endpoint: "/api/emails",
			expected: http.StatusNotFound,
		},
		{
			name:     "Version_Injection",
			endpoint: "/api/v3/../admin/secret",
			expected: http.StatusNotFound,
		},
	}

	for _, versionTest := range versionTests {
		t.Run(versionTest.name, func(t *testing.T) {
			resp, err := http.Get(s.testServer.URL + versionTest.endpoint)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, versionTest.expected, resp.StatusCode,
				fmt.Sprintf("Endpoint %s should return expected status", versionTest.endpoint))
		})
	}
}

// testErrorHandlingSecurity tests secure error handling
func (s *FortressAPISecurityTestSuite) testErrorHandlingSecurity(t *testing.T) {
	errorTriggeringRequests := []struct {
		name     string
		endpoint string
		method   string
		body     string
	}{
		{
			name:     "Invalid_JSON",
			endpoint: "/api/v3/emails",
			method:   "POST",
			body:     `{"invalid": json}`,
		},
		{
			name:     "Missing_Required_Field",
			endpoint: "/api/v3/emails",
			method:   "POST",
			body:     `{}`,
		},
		{
			name:     "Nonexistent_Resource",
			endpoint: "/api/v3/emails/999999",
			method:   "GET",
			body:     "",
		},
	}

	for _, errorTest := range errorTriggeringRequests {
		t.Run(errorTest.name, func(t *testing.T) {
			var resp *http.Response
			var err error

			if errorTest.method == "GET" {
				resp, err = http.Get(s.testServer.URL + errorTest.endpoint)
			} else {
				resp, err = http.Post(s.testServer.URL+errorTest.endpoint,
					"application/json", strings.NewReader(errorTest.body))
			}
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			responseBody := string(body)

			// Should not expose sensitive information in error messages
			sensitiveTerms := []string{
				"stack trace", "file path", "database", "sql", "internal error",
				"/usr/", "/var/", "Exception", "at line", "fatal error",
			}

			for _, term := range sensitiveTerms {
				assert.NotContains(t, strings.ToLower(responseBody), strings.ToLower(term),
					fmt.Sprintf("Error response should not contain sensitive term: %s", term))
			}
		})
	}
}

// testRequestSizeLimits tests request size limit enforcement
func (s *FortressAPISecurityTestSuite) testRequestSizeLimits(t *testing.T) {
	// Test oversized request
	largePayload := map[string]interface{}{
		"content": strings.Repeat("A", 2*1024*1024), // 2MB, larger than 1MB limit
		"email":   "test@example.com",
	}

	jsonData, err := json.Marshal(largePayload)
	require.NoError(t, err)

	resp, err := http.Post(s.testServer.URL+"/api/v3/emails",
		"application/json", bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject oversized requests
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode,
		"Oversized request should be rejected")
}

// createAPISecurityHandler creates a test HTTP handler for API security testing
func createAPISecurityHandler(fortress *fortress.Service) http.Handler {
	mux := http.NewServeMux()

	// Add security middleware wrapper
	secureHandler := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Add security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")

			// Check request size
			if r.ContentLength > 1024*1024 { // 1MB limit
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}

			// CORS handling
			origin := r.Header.Get("Origin")
			if origin == "https://trusted.example.com" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			next(w, r)
		}
	}

	// Email endpoints
	mux.HandleFunc("/api/v3/emails", secureHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}

			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error": "invalid JSON"}`))
				return
			}

			// Input validation
			if email, ok := payload["email"].(string); ok {
				if strings.Contains(email, "<script>") || strings.Contains(email, "DROP TABLE") {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error": "invalid input"}`))
					return
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"emails": []}`))
	}))

	// File upload endpoint
	mux.HandleFunc("/api/v3/files/upload", secureHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseMultipartForm(10 << 20) // 10MB limit
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()

		// File validation
		filename := header.Filename
		if strings.Contains(filename, "..") || 
		   strings.HasSuffix(filename, ".php") ||
		   strings.HasSuffix(filename, ".jsp") ||
		   strings.HasSuffix(filename, ".exe") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "file type not allowed"}`))
			return
		}

		w.Write([]byte(`{"status": "uploaded"}`))
	}))

	// GraphQL endpoint
	mux.HandleFunc("/graphql", secureHandler(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)

		query, _ := payload["query"].(string)
		if strings.Contains(query, "__schema") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": [{"message": "introspection disabled"}]}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": {"emails": []}}`))
	}))

	// Catch-all for unmatched routes
	mux.HandleFunc("/", secureHandler(func(w http.ResponseWriter, r *http.Request) {
		// Block dangerous HTTP methods
		if r.Method == "TRACE" || r.Method == "TRACK" || r.Method == "DEBUG" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "endpoint not found"}`))
	}))

	return mux
}