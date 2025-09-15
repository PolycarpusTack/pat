# MailHog Integration Catalog

**Generated**: 2025-06-11
**Purpose**: Common integration patterns and configurations

## Programming Language Integrations

### Node.js / JavaScript
```javascript
// Using nodemailer
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: 'localhost',
  port: 1025,
  ignoreTLS: true
});

// Send test email
await transporter.sendMail({
  from: 'test@example.com',
  to: 'recipient@example.com',
  subject: 'Test Email',
  text: 'This is a test',
  html: '<p>This is a test</p>'
});
```

### Python
```python
# Using smtplib
import smtplib
from email.mime.text import MIMEText

msg = MIMEText('This is a test')
msg['Subject'] = 'Test Email'
msg['From'] = 'test@example.com'
msg['To'] = 'recipient@example.com'

s = smtplib.SMTP('localhost', 1025)
s.send_message(msg)
s.quit()

# Using Django
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'localhost'
EMAIL_PORT = 1025
EMAIL_USE_TLS = False
```

### Ruby / Rails
```ruby
# Rails configuration
config.action_mailer.delivery_method = :smtp
config.action_mailer.smtp_settings = {
  address: 'localhost',
  port: 1025
}

# Using Mail gem
Mail.defaults do
  delivery_method :smtp, address: 'localhost', port: 1025
end
```

### PHP
```php
// Using PHPMailer
$mail = new PHPMailer\PHPMailer\PHPMailer();
$mail->isSMTP();
$mail->Host = 'localhost';
$mail->Port = 1025;
$mail->SMTPAuth = false;

// Laravel configuration
MAIL_MAILER=smtp
MAIL_HOST=localhost
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
```

### Java / Spring
```java
// application.properties
spring.mail.host=localhost
spring.mail.port=1025
spring.mail.properties.mail.smtp.auth=false
spring.mail.properties.mail.smtp.starttls.enable=false

// Using JavaMail
Properties props = new Properties();
props.put("mail.smtp.host", "localhost");
props.put("mail.smtp.port", "1025");
Session session = Session.getInstance(props);
```

### Go
```go
import (
    "net/smtp"
)

// Simple email
err := smtp.SendMail(
    "localhost:1025",
    nil, // No auth
    "sender@example.com",
    []string{"recipient@example.com"},
    []byte("Subject: Test\r\n\r\nTest message"),
)

// Using gomail
m := gomail.NewMessage()
m.SetHeader("From", "sender@example.com")
m.SetHeader("To", "recipient@example.com")
m.SetHeader("Subject", "Test")
m.SetBody("text/plain", "Test message")

d := gomail.NewDialer("localhost", 1025, "", "")
```

### .NET / C#
```csharp
// Using SmtpClient
var client = new SmtpClient("localhost", 1025)
{
    EnableSsl = false,
    UseDefaultCredentials = false
};

var message = new MailMessage(
    "sender@example.com",
    "recipient@example.com",
    "Test Subject",
    "Test Body"
);

await client.SendMailAsync(message);

// appsettings.json
{
  "EmailSettings": {
    "SmtpHost": "localhost",
    "SmtpPort": 1025,
    "EnableSsl": false
  }
}
```

## Testing Framework Integration

### Cypress
```javascript
// cypress.config.js
module.exports = {
  e2e: {
    env: {
      MAILHOG_API: 'http://localhost:8025/api/v2'
    }
  }
}

// Test command
Cypress.Commands.add('getLastEmail', () => {
  return cy.request('GET', `${Cypress.env('MAILHOG_API')}/messages?limit=1`)
    .then(response => response.body.messages[0]);
});

// Usage in test
cy.getLastEmail().then(email => {
  expect(email.Content.Headers.Subject[0]).to.equal('Welcome');
});
```

### Playwright
```javascript
// playwright.config.js
export default {
  use: {
    baseURL: 'http://localhost:8025',
  }
};

// Test helper
async function getLastEmail(page) {
  const response = await page.request.get('/api/v2/messages?limit=1');
  const data = await response.json();
  return data.messages[0];
}

// Test usage
const email = await getLastEmail(page);
expect(email.Content.Headers.Subject[0]).toBe('Reset Password');
```

### Jest
```javascript
// email-helper.js
const axios = require('axios');

module.exports = {
  async getEmails() {
    const response = await axios.get('http://localhost:8025/api/v2/messages');
    return response.data.messages;
  },
  
  async deleteAllEmails() {
    await axios.delete('http://localhost:8025/api/v1/messages');
  },
  
  async findEmail(subject) {
    const emails = await this.getEmails();
    return emails.find(e => 
      e.Content.Headers.Subject && 
      e.Content.Headers.Subject[0].includes(subject)
    );
  }
};

// Test usage
beforeEach(async () => {
  await emailHelper.deleteAllEmails();
});

test('password reset email', async () => {
  // Trigger password reset
  await requestPasswordReset('user@example.com');
  
  // Check email
  const email = await emailHelper.findEmail('Password Reset');
  expect(email).toBeDefined();
  expect(email.Content.Body).toContain('reset link');
});
```

## CI/CD Integration

### GitHub Actions
```yaml
services:
  mailhog:
    image: mailhog/mailhog:v1.0.1
    ports:
      - 1025:1025
      - 8025:8025

steps:
  - name: Run tests
    run: npm test
    env:
      SMTP_HOST: localhost
      SMTP_PORT: 1025
      
  - name: Verify emails sent
    run: |
      EMAIL_COUNT=$(curl -s http://localhost:8025/api/v2/messages | jq '.total')
      if [ "$EMAIL_COUNT" -eq 0 ]; then
        echo "No emails were sent!"
        exit 1
      fi
```

### GitLab CI
```yaml
services:
  - name: mailhog/mailhog:v1.0.1
    alias: mailhog

variables:
  SMTP_HOST: mailhog
  SMTP_PORT: 1025

test:
  script:
    - npm test
    - curl http://mailhog:8025/api/v2/messages
```

### Jenkins
```groovy
pipeline {
  agent any
  
  stages {
    stage('Setup') {
      steps {
        sh 'docker run -d --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog:v1.0.1'
      }
    }
    
    stage('Test') {
      environment {
        SMTP_HOST = 'localhost'
        SMTP_PORT = '1025'
      }
      steps {
        sh 'npm test'
      }
    }
    
    stage('Verify') {
      steps {
        sh '''
          EMAILS=$(curl -s http://localhost:8025/api/v2/messages | jq .total)
          echo "Captured $EMAILS emails"
        '''
      }
    }
  }
  
  post {
    always {
      sh 'docker stop mailhog && docker rm mailhog'
    }
  }
}
```

## Docker Compose Patterns

### Development Environment
```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      MAIL_HOST: mailhog
      MAIL_PORT: 1025
    depends_on:
      - mailhog

  mailhog:
    image: mailhog/mailhog:v1.0.1
    ports:
      - "1025:1025"
      - "8025:8025"
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

### Test Environment with Persistence
```yaml
version: '3.8'
services:
  mailhog:
    image: mailhog/mailhog:v1.0.1
    environment:
      MH_STORAGE: mongodb
      MH_MONGO_URI: mongodb://mongo:27017
    ports:
      - "1025:1025"
      - "8025:8025"
    depends_on:
      - mongo

  mongo:
    image: mongo:7.0
    volumes:
      - mailhog-data:/data/db

volumes:
  mailhog-data:
```

## Monitoring Integration

### Prometheus Metrics (Custom Exporter)
```go
// mailhog_exporter.go
var (
    messagesTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "mailhog_messages_total",
            Help: "Total number of messages received",
        },
    )
    
    messagesStored = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "mailhog_messages_stored",
            Help: "Current number of messages in storage",
        },
    )
)

// Collect metrics via API
func collectMetrics() {
    resp, _ := http.Get("http://localhost:8025/api/v2/messages")
    var data struct{ Total int }
    json.NewDecoder(resp.Body).Decode(&data)
    messagesStored.Set(float64(data.Total))
}
```

### Health Checks
```yaml
# docker-compose.yml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8025/api/v2/messages?limit=1"]
  interval: 30s
  timeout: 10s
  retries: 3

# Kubernetes
livenessProbe:
  httpGet:
    path: /api/v2/messages?limit=1
    port: 8025
  initialDelaySeconds: 10
  periodSeconds: 30
```

## Common Issues and Solutions

### Issue: "Connection refused"
**Solution**: Ensure MailHog is running and ports are exposed
```bash
docker ps | grep mailhog
netstat -an | grep 1025
```

### Issue: "Messages not appearing"
**Solution**: Check storage backend and API endpoint
```bash
curl http://localhost:8025/api/v2/messages
```

### Issue: "Authentication required"
**Solution**: Provide credentials or disable auth
```bash
# With auth
curl -u username:password http://localhost:8025/api/v2/messages

# Disable auth
docker run -d mailhog/mailhog # No MH_AUTH_FILE
```