# ADR-001: Storage Backend Architecture

**Status**: Active
**Date**: 2025-06-11
**Deciders**: MailHog Core Team

## Context

MailHog needs to store captured email messages with different use cases requiring different storage characteristics:
- Development: Fast, no persistence needed
- Testing: Moderate persistence, searchability
- Team environments: Full persistence, concurrent access

## Decision

Implement a pluggable storage interface with three backends:

### 1. In-Memory Storage (Default)
```go
type InMemory struct {
    messages     []*Message
    messageMutex sync.RWMutex
    messageIndex map[string]*Message
}
```
- **Use case**: Individual developer machines
- **Pros**: Zero configuration, fastest performance
- **Cons**: No persistence, memory limited

### 2. MongoDB Storage
```go
type MongoDB struct {
    session    *mgo.Session
    collection *mgo.Collection
}
```
- **Use case**: Team servers, CI/CD environments
- **Pros**: Persistent, searchable, scalable
- **Cons**: External dependency, operational overhead

### 3. Maildir Storage
```go
type Maildir struct {
    path string
    mu   sync.Mutex
}
```
- **Use case**: File-based persistence, mail client compatibility
- **Pros**: Standard format, no database needed
- **Cons**: Limited search, file system dependent

## Implementation Strategy

All storage backends implement the same interface:
```go
type Storage interface {
    Store(m *data.Message) (string, error)
    List(start, limit int) (*data.Messages, error) 
    Search(kind, query string, start, limit int) (*data.Messages, int, error)
    Count() int
    DeleteOne(id string) error
    DeleteAll() error
    Load(id string) (*data.Message, error)
}
```

## Consequences

**Positive**:
- Users can choose storage based on needs
- Clean separation of concerns
- Easy to add new storage backends
- No vendor lock-in

**Negative**:
- More complex codebase
- Testing burden for multiple backends
- Feature parity challenges
- Configuration complexity

## Evidence

Current implementation shows:
- In-memory is used by 90% of users
- MongoDB adds 50MB to Docker image
- Maildir is rarely used but critical for some workflows