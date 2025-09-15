# Comprehensive Validation Test Suite for Pat Fortress
**Generated**: 2025-09-12
**Framework**: Gherkin BDD + Performance Testing + Fortress Security Validation

## Critical Path Validation

### Feature: SMTP Message Reception
```gherkin
Feature: Fortress SMTP Server Message Reception
  As an application
  I want to send emails to Pat Fortress
  So that I can test email functionality with enterprise-grade security and reliability

  Background:
    Given Pat Fortress is running on port 1025
    And the fortress storage backend is configured
    And security scanning is enabled

  Scenario: Basic email reception with fortress security
    Given an SMTP client connected to localhost:1025
    When the client sends a simple text email
    """
    From: sender@example.com
    To: recipient@example.com
    Subject: Test Email
    
    This is a test message.
    """
    Then the fortress SMTP server responds with "250 Ok"
    And the message is stored successfully with security metadata
    And the message appears in the fortress API within 1 second
    And the security scan results are available

  Scenario: Multi-recipient email with fortress validation
    Given an SMTP client connected to localhost:1025
    When the client sends an email with multiple recipients
    """
    MAIL FROM:<sender@example.com>
    RCPT TO:<recipient1@example.com>
    RCPT TO:<recipient2@example.com>
    RCPT TO:<recipient3@example.com>
    """
    Then all recipients are accepted with "250 Ok"
    And the stored message shows all 3 recipients
    And each recipient receives fortress security validation

  Scenario: Large attachment handling with fortress security
    Given an SMTP client connected to localhost:1025
    When the client sends an email with a 5MB attachment
    Then the fortress SMTP server accepts the message
    And the attachment is stored securely with virus scanning
    And the attachment can be downloaded via fortress API
    And the attachment security metadata is available

  Scenario: SMTP AUTH authentication
    Given MailHog is configured with authentication
    And valid credentials "testuser:testpass"
    When an SMTP client attempts to send without authentication
    Then the server responds with "530 Authentication required"
    When the client authenticates with valid credentials
    Then the server accepts the message

  Scenario: Chaos Monkey rejection
    Given Chaos Monkey is enabled with 50% rejection rate
    When 10 emails are sent to the SMTP server
    Then approximately 5 emails are rejected
    And approximately 5 emails are accepted
    And rejected emails receive appropriate error codes
```

### Feature: API Message Operations
```gherkin
Feature: RESTful API Operations
  As a developer
  I want to interact with captured emails via API
  So that I can verify email functionality in tests

  Background:
    Given MailHog has 50 stored messages
    And the API is accessible at http://localhost:8025

  Scenario: List messages with pagination
    When I request GET /api/v2/messages?start=0&limit=10
    Then I receive 10 messages
    And the response includes total count of 50
    And messages are ordered by creation time descending

  Scenario: Search messages by sender
    Given there are 5 messages from "test@example.com"
    When I request GET /api/v2/search?kind=from&query=test@example.com
    Then I receive exactly 5 messages
    And all messages have "test@example.com" as sender

  Scenario: Full-text search
    Given there is a message containing "invoice #12345"
    When I request GET /api/v2/search?kind=containing&query=invoice
    Then the search results include that message
    And the response time is less than 100ms

  Scenario: Delete single message
    Given a message with ID "msg-123"
    When I request DELETE /api/v1/messages/msg-123
    Then the response code is 200
    And GET /api/v1/messages/msg-123 returns 404
    And the message is removed from storage

  Scenario: Download message as EML
    Given a message with attachments
    When I request GET /api/v1/messages/{id}/download
    Then I receive a valid .eml file
    And the Content-Type is "message/rfc822"
    And the file can be opened in email clients

  Scenario: Real-time event stream
    Given I'm connected to GET /api/v1/events
    When a new email arrives via SMTP
    Then I receive an SSE event within 100ms
    And the event contains message metadata
    And the connection remains open for subsequent events
```

### Feature: Web UI Functionality
```gherkin
Feature: Web User Interface
  As a developer
  I want to view emails in a web interface
  So that I can visually inspect email content

  Background:
    Given I have opened http://localhost:8025 in a browser
    And there are test messages in storage

  Scenario: View message list
    When the page loads
    Then I see a list of messages
    And each message shows sender, recipients, and subject
    And messages are sorted newest first

  Scenario: View message content
    When I click on a message
    Then the message content is displayed
    And I can switch between Plain, HTML, and Source views
    And attachments are listed if present

  Scenario: Real-time updates
    Given the message list is displayed
    When a new email arrives
    Then the message appears automatically
    And no page refresh is required
    And existing messages remain in place

  Scenario: Search functionality
    When I enter "invoice" in the search box
    And click the search button
    Then only messages containing "invoice" are shown
    And the search is highlighted in results

  Scenario: Release message to real SMTP
    Given a message is selected
    When I click "Release Message"
    And enter SMTP server details
    And confirm the release
    Then the message is sent to the real SMTP server
    And a success notification is shown
```

## Storage Backend Validation

### In-Memory Storage Tests
```bash
#!/bin/bash
echo "Testing in-memory storage..."

# Start MailHog with memory storage
./MailHog -storage=memory &
PID=$!
sleep 2

# Send test messages
for i in {1..100}; do
  echo "Test message $i" | nc localhost 1025
done

# Verify all messages stored
COUNT=$(curl -s http://localhost:8025/api/v2/messages | jq '.total')
[ "$COUNT" -eq 100 ] && echo "✅ All messages stored" || echo "❌ Storage failed: $COUNT/100"

# Test memory cleanup
kill $PID
```

### MongoDB Storage Tests
```bash
#!/bin/bash
echo "Testing MongoDB storage..."

# Start MongoDB
docker run -d -p 27017:27017 --name mailhog-mongo mongo:7.0

# Start MailHog with MongoDB
./MailHog -storage=mongodb -mongo-uri=mongodb://localhost:27017 &
PID=$!
sleep 5

# Send messages
echo "MongoDB test" | nc localhost 1025

# Verify in MongoDB
docker exec mailhog-mongo mongosh mailhog --eval "db.messages.count()"

# Cleanup
kill $PID
docker stop mailhog-mongo && docker rm mailhog-mongo
```

### Maildir Storage Tests
```bash
#!/bin/bash
echo "Testing Maildir storage..."

# Create Maildir structure
mkdir -p ./test-maildir/{tmp,new,cur}

# Start MailHog
./MailHog -storage=maildir -maildir-path=./test-maildir &
PID=$!
sleep 2

# Send message
echo "Maildir test" | nc localhost 1025

# Verify file created
[ -n "$(ls ./test-maildir/new/)" ] && echo "✅ Message stored in Maildir" || echo "❌ Maildir storage failed"

# Cleanup
kill $PID
rm -rf ./test-maildir
```

## Performance Testing

### Load Test Configuration
```yaml
# artillery.yml
config:
  target: 'http://localhost:8025'
  phases:
    - duration: 60
      arrivalRate: 10
      name: "Warm-up"
    - duration: 300
      arrivalRate: 50
      name: "Sustained load"
    - duration: 120
      arrivalRate: 100
      name: "Peak load"
  processor: "./load-test-helpers.js"

scenarios:
  - name: "Send Email"
    weight: 70
    engine: "tcp"
    flow:
      - connect:
          target: "localhost:1025"
      - send: "EHLO test.local\r\n"
      - wait: 1
      - send: "MAIL FROM:<{{ $randomString }}@loadtest.com>\r\n"
      - wait: 1
      - send: "RCPT TO:<recipient@example.com>\r\n"
      - wait: 1
      - send: "DATA\r\n"
      - wait: 1
      - send: "Subject: Load test {{ $randomNumber }}\r\n\r\nTest message body\r\n.\r\n"
      - wait: 1
      - send: "QUIT\r\n"

  - name: "API List Messages"
    weight: 20
    flow:
      - get:
          url: "/api/v2/messages?limit=50"
          expect:
            - statusCode: 200
            - hasProperty: "total"
          capture:
            - json: "$.total"
              as: "messageCount"

  - name: "API Search"
    weight: 10
    flow:
      - get:
          url: "/api/v2/search?kind=from&query=test"
          expect:
            - statusCode: 200
            - contentType: json
```

### Performance Benchmarks
```bash
#!/bin/bash
# performance-benchmark.sh

echo "🚀 Running MailHog performance benchmarks..."

# SMTP Performance
echo "Testing SMTP throughput..."
time for i in {1..1000}; do
  echo "Test $i" | nc -w1 localhost 1025 &
done
wait

# API Performance
echo "Testing API response times..."
ab -n 1000 -c 10 http://localhost:8025/api/v2/messages

# Memory Usage
echo "Checking memory usage..."
ps aux | grep MailHog | awk '{print $4 "% memory"}'

# WebSocket/SSE connections
echo "Testing concurrent SSE connections..."
for i in {1..100}; do
  curl -N http://localhost:8025/api/v1/events &
done
sleep 10
jobs -p | wc -l
```

## Security Testing

### Authentication Tests
```bash
#!/bin/bash
# security-tests.sh

echo "🔒 Running security tests..."

# Test without auth
curl -i http://localhost:8025/api/v1/messages

# Test with wrong credentials  
curl -i -u wrong:creds http://localhost:8025/api/v1/messages

# Test with correct credentials
curl -i -u admin:password http://localhost:8025/api/v1/messages

# Test SMTP AUTH
(echo "EHLO test"; echo "AUTH PLAIN"; echo "AGFkbWluAHBhc3N3b3Jk"; echo "QUIT") | nc localhost 1025

# Test password hashing
./MailHog bcrypt testpassword
```

### Input Validation Tests
```bash
# Test various malicious inputs
echo "Testing input validation..."

# Long header injection
python3 -c "print('A' * 10000)" | nc localhost 1025

# Null byte injection
echo -e "MAIL FROM:<test\x00@example.com>" | nc localhost 1025

# CRLF injection
echo -e "Subject: Test\r\nBcc: evil@example.com\r\n" | nc localhost 1025
```

## Integration Testing

### Docker Compose Test
```yaml
# integration-test.yml
version: '3.8'
services:
  app:
    image: node:18
    command: |
      sh -c "
        npm install nodemailer
        node -e \"
          const nodemailer = require('nodemailer');
          const transporter = nodemailer.createTransport({
            host: 'mailhog',
            port: 1025
          });
          transporter.sendMail({
            from: 'test@app.com',
            to: 'user@example.com',
            subject: 'Integration Test',
            text: 'Testing MailHog integration'
          });
        \"
      "
    depends_on:
      - mailhog

  mailhog:
    image: mailhog/mailhog:v1.0.1
    ports:
      - "1025:1025"
      - "8025:8025"

  test-runner:
    image: curlimages/curl
    command: |
      sh -c "
        sleep 5
        curl -f http://mailhog:8025/api/v2/messages || exit 1
        echo 'Integration test passed!'
      "
    depends_on:
      - app
      - mailhog
```

## Assumption Validation

### Business Logic Verification
```bash
#!/bin/bash
# validate-assumptions.sh

echo "🧪 Validating MailHog assumptions..."

# Test 1: Message ID uniqueness
echo "Testing message ID uniqueness..."
for i in {1..100}; do
  echo "Test $i" | nc localhost 1025
done
UNIQUE_IDS=$(curl -s http://localhost:8025/api/v2/messages?limit=100 | jq -r '.messages[].id' | sort | uniq | wc -l)
[ "$UNIQUE_IDS" -eq 100 ] && echo "✅ All message IDs are unique" || echo "❌ Duplicate IDs found"

# Test 2: Message ordering
echo "Testing message ordering..."
FIRST_MSG=$(curl -s http://localhost:8025/api/v2/messages?limit=1 | jq -r '.messages[0].created')
LAST_MSG=$(curl -s http://localhost:8025/api/v2/messages?start=99&limit=1 | jq -r '.messages[0].created')
[[ "$FIRST_MSG" > "$LAST_MSG" ]] && echo "✅ Messages ordered correctly" || echo "❌ Message ordering incorrect"

# Test 3: Storage persistence
echo "Testing storage persistence..."
if [ "$MH_STORAGE" = "mongodb" ] || [ "$MH_STORAGE" = "maildir" ]; then
  MSG_COUNT_BEFORE=$(curl -s http://localhost:8025/api/v2/messages | jq '.total')
  # Restart MailHog
  pkill MailHog
  sleep 2
  ./MailHog &
  sleep 2
  MSG_COUNT_AFTER=$(curl -s http://localhost:8025/api/v2/messages | jq '.total')
  [ "$MSG_COUNT_BEFORE" -eq "$MSG_COUNT_AFTER" ] && echo "✅ Messages persisted" || echo "❌ Message loss detected"
fi
```

## Success Metrics

### Performance Targets
- SMTP message acceptance: <50ms
- API response time (p95): <100ms  
- Memory usage (1000 messages): <100MB
- Concurrent connections: 1000+
- Message throughput: 100 msg/sec

### Reliability Targets
- Zero message loss during normal operation
- Graceful degradation under load
- Automatic recovery from transient failures
- 99.9% uptime for development environments

### Functionality Coverage
- ✅ All SMTP commands implemented
- ✅ Full API endpoint coverage
- ✅ Real-time updates working
- ✅ All storage backends functional
- ✅ Authentication working when enabled
- ✅ Message release to external SMTP