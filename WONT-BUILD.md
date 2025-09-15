# Features We Won't Build (Unless Users Prove Need)

This document explains what **Pat Fortress intentionally doesn't do** and why. This prevents feature creep and keeps the tool focused on email testing.

## ❌ **Database Persistence (PostgreSQL/MongoDB)**

**Why not**: Memory storage works perfectly for email testing. Developers usually:
- Test emails locally during development
- Don't need emails to persist across restarts
- Want fast, zero-setup experience

**Would consider if**:
- 50+ GitHub issues requesting persistence
- Clear use cases for long-term email storage
- Teams running Pat in shared environments

**Evidence needed**: Survey data showing persistence is a blocker for adoption

---

## ❌ **Enterprise Authentication (OAuth/SAML/LDAP)**

**Why not**: Pat is a **local development tool**. Most developers run it on localhost where authentication adds friction without security benefit.

**Would consider if**:
- Multiple teams request shared Pat instances
- Corporate environments need integration
- Security requirements for team-shared environments

**Evidence needed**:
- GitHub issues from enterprise users
- Clear team collaboration workflow descriptions

---

## ❌ **Complex Rate Limiting (Token Bucket/Redis-backed)**

**Why not**: Email testing doesn't generate enough traffic to need sophisticated rate limiting. Simple per-IP counting prevents basic abuse.

**Would consider if**:
- Users report abuse issues
- High-traffic integration testing scenarios emerge

**Evidence needed**: Performance problems with current simple approach

---

## ❌ **Full MIME Parsing with Attachment Extraction**

**Why not**: Current basic detection (shows "has attachments: true") covers 90% of email testing needs. Full parsing adds complexity for minimal user benefit.

**Would consider if**:
- Developers need to inspect attachment contents
- Email testing workflows require attachment validation

**Evidence needed**:
- Specific workflows blocked by lack of attachment extraction
- User requests for attachment download/preview

---

## ❌ **Microservices Architecture**

**Why not**: Pat is a single-purpose tool. Breaking it into microservices would add deployment complexity without benefits for the email testing use case.

**Would consider if**: Never. This is architectural over-engineering.

---

## ❌ **Comprehensive Observability (Prometheus/Grafana/Distributed Tracing)**

**Why not**: Pat runs locally for email testing. Basic health checks and simple metrics are sufficient.

**Would consider if**:
- Production deployments become common
- Performance issues need detailed monitoring
- Integration with existing monitoring stacks requested

**Evidence needed**: Users actually deploying Pat in production environments

---

## ❌ **GraphQL API Integration**

**Why not**: The REST API provides everything needed for email testing UIs. GraphQL adds complexity without solving a user problem.

**Would consider if**:
- Modern UI frameworks require GraphQL
- Developers build custom dashboards needing flexible queries

**Evidence needed**:
- Specific UI limitations with REST API
- Community-built integrations requesting GraphQL

---

## ❌ **Message Queuing (RabbitMQ/Kafka Integration)**

**Why not**: Email testing doesn't need message queuing. Pat captures emails directly from SMTP.

**Would consider if**: Never. This is solving problems that don't exist.

---

## ❌ **Container Orchestration (Kubernetes Operators/Helm Charts)**

**Why not**: Docker Compose is sufficient for local development. Kubernetes adds operational overhead for a development tool.

**Would consider if**:
- Teams standardize on Kubernetes for all local development
- Clear operational benefits over Docker Compose

**Evidence needed**:
- Survey showing Docker Compose insufficient
- Kubernetes-specific features needed

---

## ✅ **What We WILL Build (With Evidence)**

### **Small Quality-of-Life Improvements**
- Better error messages (if users report confusion)
- Additional MailHog compatibility endpoints (if migration issues arise)
- Simple UI improvements (if usability feedback provided)

### **Evidence-Based Threshold**
We'll consider features when we see:
- **5+ GitHub issues** requesting the same capability
- **Clear use case descriptions** showing current limitations
- **Volunteer maintainers** willing to support the feature long-term

---

## 📝 **How to Request Features**

1. **Open a GitHub issue** with:
   - Your specific use case
   - Why current functionality doesn't work
   - How this would improve your email testing workflow

2. **Provide evidence** of broader need:
   - Survey other developers on your team
   - Reference similar requests in other projects
   - Show community interest (upvotes, comments)

3. **Consider maintenance burden**:
   - Are you willing to help maintain this feature?
   - Will this add complexity that affects all users?
   - Is there a simpler solution that meets your need?

---

## 🎯 **Pat's Mission**

**Pat Fortress exists to make email testing simple and reliable for developers.**

Every feature decision should ask: "Does this make email testing better for the majority of developers, or does it add complexity that only helps a few edge cases?"

When in doubt, we choose **simplicity over sophistication**.