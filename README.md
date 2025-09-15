# Pat Fortress - Simple Email Testing Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pat Fortress is a **reliable, simple email testing tool** for developers. A modern MailHog replacement that focuses on the essentials: capturing and inspecting emails during development.

## 🚀 **Quick Start**

```bash
# Download and run (or build from source)
./pat-fortress

# Test it works
curl -X POST http://localhost:8025/api/v1/messages
```

Pat runs on:
- **SMTP Server**: `localhost:1025` (configure your app to send emails here)
- **Web UI**: `localhost:8025` (view captured emails)

## ✨ **What Pat Does**

- ✅ **Captures emails** sent to `localhost:1025`
- ✅ **Web interface** to view/inspect messages
- ✅ **REST API** for automation (MailHog compatible)
- ✅ **MIME detection** shows if emails have attachments
- ✅ **Real-time updates** via WebSocket
- ✅ **Basic protection** against spam/abuse
- ✅ **AI-powered analysis** for spam detection and deliverability insights (optional)

## 🎯 **Why Pat Over MailHog?**

- **More reliable**: Fixed critical bugs (index bounds, uptime calculation)
- **Better defaults**: Sensible rate limiting and connection management
- **Cleaner config**: Consolidated configuration system
- **Active development**: Regular updates and maintenance

## ⚙️ **Configuration**

### **Environment Variables**
```bash
export PAT_SMTP_BIND_ADDR=0.0.0.0:1025
export PAT_HTTP_BIND_ADDR=0.0.0.0:8025
export PAT_LOG_LEVEL=info

# AI Analysis (optional)
export PAT_OPENAI_API_KEY=sk-your-api-key-here
export PAT_OPENAI_MODEL=gpt-3.5-turbo
```

### **Command Line Flags**
```bash
./pat-fortress \
  --smtp-bind-addr=0.0.0.0:1025 \
  --api-bind-addr=0.0.0.0:8025 \
  --max-message-size=10485760 \
  --enable-auth=false \
  --log-level=info \
  --enable-ai=true \
  --openai-api-key=sk-your-key-here
```

### **Docker**
```bash
docker run -p 1025:1025 -p 8025:8025 pat-fortress:latest
```

## 📡 **API Compatibility**

Pat is **100% MailHog API compatible**:

```bash
# List messages
GET /api/v1/messages

# Get specific message
GET /api/v1/messages/{id}

# Delete message
DELETE /api/v1/messages/{id}

# Search messages
GET /api/v2/search?kind=from&query=test@example.com
```

**Plus new endpoints:**
```bash
# Health check
GET /api/v3/health

# Real metrics
GET /api/v3/metrics

# Security scan
POST /api/v3/security/scan/{id}

# AI email analysis (optional)
POST /api/v3/ai/analyze/{id}
GET /api/v3/ai/status
```

## 🤖 **AI-Powered Email Analysis**

Pat can analyze your emails to help identify potential delivery issues during development:

### **What It Checks**
- ✅ **Spam risk** - Identifies content that might trigger spam filters
- ✅ **Content issues** - Flags problematic links, formatting, or tone
- ✅ **Deliverability** - Checks headers and structure for delivery problems
- ✅ **Practical suggestions** - Provides actionable fixes for developers

### **Example Analysis Response**
```json
{
  "spam_risk": {
    "score": 25,
    "level": "low",
    "reasons": ["Subject contains urgency keywords"]
  },
  "content_issues": [
    {
      "type": "security",
      "severity": "medium",
      "description": "Non-HTTPS links found",
      "suggestion": "Use HTTPS links for better security"
    }
  ],
  "summary": "Email looks good for delivery",
  "confidence": 0.85
}
```

### **Setup**
```bash
# Basic setup - uses free basic analysis
./pat-fortress

# With OpenAI for enhanced analysis
export PAT_OPENAI_API_KEY=sk-your-api-key-here
./pat-fortress
```

**Note**: AI analysis works without an API key (basic checks), but OpenAI integration provides more detailed insights.

## 🔌 **Framework Integration**

### **Node.js/Express**
```javascript
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransporter({
  host: 'localhost',
  port: 1025,
  secure: false, // Pat doesn't require TLS
  auth: false    // No authentication needed
});

// Send test email
await transporter.sendMail({
  from: 'test@yourapp.com',
  to: 'user@example.com',
  subject: 'Welcome!',
  html: '<h1>Welcome to our app!</h1>'
});
```

### **Python/Django**
```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'localhost'
EMAIL_PORT = 1025
EMAIL_USE_TLS = False
EMAIL_USE_SSL = False

# In your code
from django.core.mail import send_mail

send_mail(
    'Welcome!',
    'Thanks for signing up.',
    'noreply@yourapp.com',
    ['user@example.com'],
    html_message='<h1>Welcome!</h1>'
)
```

### **Ruby/Rails**
```ruby
# config/environments/development.rb
config.action_mailer.delivery_method = :smtp
config.action_mailer.smtp_settings = {
  address: 'localhost',
  port: 1025,
  domain: 'yourapp.com'
}

# In your mailer
class WelcomeMailer < ApplicationMailer
  def welcome_email(user)
    mail(to: user.email, subject: 'Welcome!')
  end
end
```

### **PHP/Laravel**
```php
// .env
MAIL_MAILER=smtp
MAIL_HOST=localhost
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

// In your code
Mail::to('user@example.com')->send(new WelcomeMail($user));
```

### **Java/Spring Boot**
```yaml
# application.yml
spring:
  mail:
    host: localhost
    port: 1025
    properties:
      mail:
        smtp:
          auth: false
          starttls:
            enable: false
```

```java
@Autowired
private JavaMailSender mailSender;

public void sendWelcomeEmail(String to) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setSubject("Welcome!");
    message.setText("Thanks for signing up!");
    mailSender.send(message);
}
```

### **VisualWorks Smalltalk**
```smalltalk
"Configure SMTP settings for Pat Fortress"
| smtpClient message |

"Create SMTP client pointing to Pat"
smtpClient := SMTPClient new
    host: 'localhost';
    port: 1025;
    yourself.

"Create and send email message"
message := MailMessage new
    from: (MailAddress fromString: 'test@yourapp.com');
    to: (OrderedCollection with: (MailAddress fromString: 'user@example.com'));
    subject: 'Welcome from Smalltalk!';
    body: 'This email was sent from VisualWorks Smalltalk.';
    yourself.

"Send the message via Pat Fortress"
smtpClient sendMessage: message.

"Clean up"
smtpClient close.
```

### **Alternative Smalltalk approach using raw socket:**
```smalltalk
"Direct socket approach for maximum control"
| socket stream |

socket := Socket newTCP.
[
    socket connectTo: (SocketAddress byName: 'localhost' port: 1025).
    stream := socket readWriteStream.

    "SMTP conversation"
    stream nextPutAll: 'HELO yourapp.com'; cr; lf; flush.
    stream nextPutAll: 'MAIL FROM:<test@yourapp.com>'; cr; lf; flush.
    stream nextPutAll: 'RCPT TO:<user@example.com>'; cr; lf; flush.
    stream nextPutAll: 'DATA'; cr; lf; flush.
    stream nextPutAll: 'Subject: Test from Smalltalk'; cr; lf.
    stream nextPutAll: 'From: test@yourapp.com'; cr; lf.
    stream nextPutAll: 'To: user@example.com'; cr; lf.
    stream nextPutAll: ''; cr; lf.
    stream nextPutAll: 'Hello from VisualWorks Smalltalk!'; cr; lf.
    stream nextPutAll: '.'; cr; lf; flush.
    stream nextPutAll: 'QUIT'; cr; lf; flush.
] ensure: [
    socket close
].
```

## 📧 **Testing Email Scenarios**

### **Outbound Email Testing (Primary Use Case)**
Test services that **send** emails during development:

```bash
# 1. Start Pat Fortress
./pat-fortress

# 2. Configure your app to send emails to Pat
# Your app sends emails → Pat captures them → View in browser

# 3. View captured emails
open http://localhost:8025

# 4. Test with AI analysis
curl -X POST http://localhost:8025/api/v3/ai/analyze/message-id-123
```

### **Inbound Email Testing (Direct SMTP)**
Test services that **receive/process** emails:

```bash
# Send test email directly to Pat via SMTP
telnet localhost 1025
> HELO test.com
> MAIL FROM:<sender@test.com>
> RCPT TO:<recipient@yourapp.com>
> DATA
> Subject: Test Email
>
> This is a test message.
> .
> QUIT

# Or use automation
echo -e "Subject: Test\n\nTest body" | nc localhost 1025
```

### **CI/CD Email Testing**
Automate email testing in your pipeline:

```bash
# Start Pat in background
./pat-fortress &
PAT_PID=$!

# Run your tests (they send emails to localhost:1025)
npm test

# Verify emails were sent
EMAILS=$(curl -s http://localhost:8025/api/v1/messages | jq '.count')
if [ "$EMAILS" -eq "0" ]; then
  echo "❌ No emails sent during test"
  exit 1
fi

# Run AI analysis on all emails
for id in $(curl -s http://localhost:8025/api/v1/messages | jq -r '.messages[].ID'); do
  curl -X POST http://localhost:8025/api/v3/ai/analyze/$id
done

# Cleanup
kill $PAT_PID
```

## 🔧 **Development**

```bash
# Build
go build -o pat-fortress

# Run tests
go test ./...

# Development with hot reload
go run main.go --log-level=debug
```

## 📊 **What Pat Doesn't Do**

See [WONT-BUILD.md](./WONT-BUILD.md) for features we **intentionally don't include** to keep Pat focused on email testing.

**Summary**: No databases, no microservices, no enterprise auth. Keep it simple.

## 🤝 **Contributing**

1. **Bug reports**: Always welcome
2. **Feature requests**: Please read [WONT-BUILD.md](./WONT-BUILD.md) first
3. **Pull requests**: Focus on email testing improvements

**Philosophy**: We value **simplicity over sophistication**. Every change should make email testing better for most developers.

## 📄 **License**

MIT License - Use freely for development and testing.

## 🙏 **Credits**

Built on the foundation of [MailHog](https://github.com/mailhog/MailHog) by Ian Kent.
Pat Fortress modernizes the codebase while maintaining compatibility.

---

**Pat Fortress: Email testing that just works.** 📧# pat
