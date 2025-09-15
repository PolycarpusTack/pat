# ADR-002: API Versioning Strategy

**Status**: Active
**Date**: 2025-06-11
**Deciders**: MailHog Core Team

## Context

MailHog's API started without versioning, then added v1 and v2 endpoints. Need clear versioning strategy for backward compatibility while allowing evolution.

## Decision

### API Version Strategy
1. **v1 API**: Frozen, no new features
   - Path: `/api/v1/*`
   - Status: Deprecated but supported
   - Changes: Bug fixes only

2. **v2 API**: Active development
   - Path: `/api/v2/*`
   - Status: Current
   - Changes: New features allowed

### Versioning Rules
- Major versions in URL path (`/api/v1/`, `/api/v2/`)
- Breaking changes require new major version
- Minor changes via query parameters or headers
- Deprecation notices via headers

### Implementation
```go
router.PathPrefix("/api/v1/").Handler(v1.CreateAPIv1())
router.PathPrefix("/api/v2/").Handler(v2.CreateAPIv2())
```

## Consequences

**Positive**:
- Clear compatibility guarantees
- Gradual migration path
- No surprise breaking changes
- Multiple versions can coexist

**Negative**:
- Code duplication between versions
- Maintenance burden
- Confusion about which version to use
- Storage interface must support all versions

## Migration Guidelines

1. New features go in v2 only
2. v1 bugs fixed in both versions
3. Deprecation warnings after 6 months
4. Remove versions after 1 year deprecated
5. Documentation clearly marks version status