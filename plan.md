# ASM Tool - Comprehensive Development Plan

## Executive Summary

**Project**: ASM Tool (Attack Surface Management)
**Version**: 1.0.0
**Current Status**: Production-ready with technical debt
**Analysis Date**: 2026-01-04

This document provides a comprehensive analysis of the ASM Tool codebase and prioritizes actionable improvements across security, architecture, testing, documentation, and maintainability.

---

## Project Overview

### Purpose
The ASM Tool is a self-contained, Docker-based attack surface management tool designed for security practitioners managing small-to-medium organizations. It automates the discovery and monitoring of external assets including subdomains, open ports, SSL certificates, technologies, DNS records, API endpoints, URLs, email addresses, and vulnerabilities.

### Architecture
- **Pattern**: Layered architecture with modular design
  - **Core Layer**: Configuration, database persistence, notifications, reporting, scheduling
  - **Modules Layer**: 10 specialized scanning modules (subdomains, ports, certificates, technologies, DNS monitoring, nuclei scanner, URL enumeration, takeover detection, API discovery, email enumeration)
  - **Entry Point**: CLI-based interface using Click framework
- **Data Persistence**: TinyDB (JSON-based document database)
- **Containerization**: Docker with host networking support for scanning
- **Technology Stack**: Python 3.11+, external tools (nmap, subfinder, nuclei, gau, httpx)

### Key Components

| Component | File(s) | Purpose | Lines |
|-----------|-----------|---------|--------|
| CLI Entry | `asm/__main__.py` | Command-line interface | 799 |
| Configuration | `asm/core/config.py` | Config management via YAML | 132 |
| Database | `asm/core/database.py` | TinyDB persistence layer | 631 |
| Error Handler | `asm/core/error_handler.py` | Centralized error handling | 72 |
| Notifier | `asm/core/notifier.py` | Slack/email alerts | 222 |
| Reporter | `asm/core/reporter.py` | Multi-format report generation | 247 |
| Scheduler | `asm/core/scheduler.py` | Cron job management | 100 |
| Subdomains | `asm/modules/subdomains.py` | Subdomain enumeration | 164 |
| Ports | `asm/modules/ports.py` | Port scanning (nmap) | 189 |
| Certificates | `asm/modules/certificates.py` | SSL/TLS monitoring | 186 |
| Technologies | `asm/modules/technologies.py` | Tech fingerprinting | 258 |
| DNS Monitor | `asm/modules/dns_monitor.py` | DNS record tracking | 163 |
| Nuclei Scanner | `asm/modules/nuclei_scanner.py` | Vulnerability scanning | 258 |
| URLs | `asm/modules/urls.py` | URL enumeration (GAU) | 258 |
| Takeover | `asm/modules/takeover.py` | Subdomain takeover detection | 582 |
| API Discovery | `asm/modules/api_discovery.py` | API endpoint discovery | 456 |
| Emails | `asm/modules/emails.py` | Email enumeration | 381 |
| Timeouts | `asm/timeouts.py` | Timeout constants | 21 |

**Total Production Code**: ~5,083 lines

---

## Strengths

✅ **Clear modular architecture** - Well-separated core and modules
✅ **Comprehensive feature set** - 10 specialized scanning modules
✅ **Docker support** - Containerized deployment
✅ **Rich CLI** - Beautiful terminal output using Rich library
✅ **Flexible reporting** - Multiple formats (table, JSON, Markdown, HTML)
✅ **Notification system** - Slack and email integration
✅ **Error handling framework** - Centralized error handler (error_handler.py)
✅ **Recent improvements** - DateTime deprecations fixed, timeout constants extracted
✅ **Good test infrastructure** - Unit tests with fixtures, pytest configuration
✅ **Documentation** - Comprehensive README, contributing guide, CHANGELOG

---

## Critical Issues

### Security Vulnerabilities

#### 1. Command Injection Risks (HIGH)
**Files**: `asm/modules/ports.py`, `asm/modules/subdomains.py`

**Issue**: External tool commands constructed with user input without proper sanitization.

```python
# ports.py:52 - Vulnerable
cmd = ['nmap', '-p', port_str, ...]
# port_str from user input could contain shell metacharacters
```

**Impact**: Attacker could inject arbitrary commands if domain/port data is user-controlled.

**Fix Required**:
- Validate all user inputs before command construction
- Use `shlex.quote()` for shell argument escaping
- Implement allowlist validation for port numbers and domains

#### 2. Path Traversal in File Operations (MEDIUM)
**Files**: `asm/core/reporter.py`, `asm/__main__.py`

**Issue**: File paths constructed from user input without validation.

```python
# __main__.py:704 - Vulnerable
Path(output).write_text(report_content)
# If output contains "../", files could be written outside intended directory
```

**Impact**: Could write files to arbitrary locations.

**Fix Required**:
- Use `Path.resolve()` to normalize paths
- Validate paths are within expected directory
- Use `os.path.abspath()` with directory checking

#### 3. Hardcoded/Exposed Credentials (LOW)
**Files**: `config.yaml`, `asm/core/notifier.py`

**Issue**: Configuration files contain webhook URLs and SMTP credentials that may be committed to version control.

**Impact**: Exposure of sensitive configuration in git history.

**Fix Required**:
- Add `config.example.yaml` to `.gitignore`
- Document credential management best practices
- Consider environment variable support for secrets

#### 4. Insecure HTTP Requests (MEDIUM)
**Files**: `asm/modules/*.py` (multiple modules)

**Issue**: `verify=False` used throughout, disabling SSL certificate verification.

```python
# api_discovery.py:204 - Example
response = requests.get(url, timeout=10, verify=False, ...)
```

**Impact**: Vulnerable to MITM attacks, but may be intentional for self-signed certs.

**Fix Required**:
- Document why SSL verification is disabled
- Consider configurable SSL verification option
- Use proper certificate bundle for internal scanning

#### 5. Missing Input Validation (MEDIUM)
**Files**: All modules

**Issue**: No comprehensive input validation for domains, URLs, file paths.

**Examples**:
- No domain format validation (RFC 1035)
- No URL format validation
- No maximum length enforcement
- No special character filtering

**Fix Required**:
- Implement input validation utilities
- Add domain validation regex
- Add URL validation
- Add max length checks

### Architectural Issues

#### 6. God Classes Violating SRP (HIGH)
**File**: `asm/core/database.py` (631 lines)

**Issue**: Database class handles 13 different data types (subdomains, ports, certificates, technologies, DNS records, findings, scan history, domains, URLs, takeovers, APIs, emails) in a single class.

**Impact**: Difficult to test, violates Single Responsibility Principle, hard to maintain.

**Fix Required**:
- Extract repository pattern: create separate repository classes per data type
- Implement `BaseRepository` with common operations
- Each repository handles one data type

**Estimated Impact**: Reduce database.py from 631 to ~100 lines

#### 7. Missing or Incomplete Type Annotations (MEDIUM)
**Files**: All modules, particularly `api_discovery.py`, `takeover.py`

**Issue**: Inconsistent type hints, many private methods lack annotations.

**Impact**: Reduced IDE support, potential runtime errors, harder refactoring.

**Fix Required**:
- Add type hints to all public methods
- Use `TypedDict` for complex return types
- Add `->` return type annotations to all functions
- Import necessary types from `typing`

#### 8. Inconsistent Error Handling (MEDIUM)
**Files**: All modules

**Issue**: Mix of bare `except`, `except Exception`, and no error context.

```python
# Example from multiple files:
except Exception:
    pass  # Silent failure - no logging
```

**Impact**: Silent failures, difficult debugging, no error context.

**Fix Required**:
- Use centralized `@handle_errors` decorator consistently
- Always log errors with context
- Never silently swallow exceptions
- Use specific exception types where possible

#### 9. Code Duplication (MEDIUM)
**Files**: Multiple modules, CLI

**Issue**: Repetitive patterns:
- Target resolution logic in CLI (repeated in 10 commands)
- HTTP request patterns (same 20+ lines in each module)
- Notification JSON building (similar structure for summary vs alert)

**Impact**: Increased maintenance burden, potential for bugs in one place to exist in multiple places.

**Fix Required**:
- Extract target resolution helper to CLI utilities
- Create HTTP client wrapper for common request patterns
- Extract notification payload builders to separate module

#### 10. Large Method Functions (MEDIUM)
**Files**: `asm/modules/api_discovery.py`, `asm/__main__.py`

**Issue**: Some methods exceed 100 lines (e.g., `_check_graphql()` in api_discovery.py).

**Impact**: Hard to understand, test, and maintain.

**Fix Required**:
- Split large methods into smaller, focused functions
- Extract helper methods for repeated logic
- Use composition over monolithic functions

### Testing Gaps

#### 11. Incomplete Test Coverage (MEDIUM)
**Status**: 92 unit tests passing, 16% module coverage

**Missing Test Coverage**:
- No tests for: `subdomains.py`, `ports.py`, `certificates.py`, `technologies.py`, `dns_monitor.py`, `nuclei_scanner.py`, `urls.py`, `takeover.py`, `api_discovery.py`, `emails.py`
- Only core modules tested: `database.py`, `config.py`, `notifier.py`, `reporter.py`, `scheduler.py`
- No integration tests
- No end-to-end workflow tests
- No performance/stress tests

**Impact**: Untested modules may have bugs, regressions possible.

**Fix Required**:
- Add unit tests for all 10 scanning modules
- Create integration test suite for cross-module interactions
- Add smoke tests for critical workflows
- Target: 70%+ coverage (currently 16% for modules)

**Estimated Effort**: 40-60 hours of test development

#### 12. Mock External Dependencies (MEDIUM)
**Status**: Test fixtures mock external tools but don't use them in actual test files

**Issue**: Tests don't use the available mock fixtures from `tests/fixtures.py`.

**Impact**: Tests may not properly isolate external dependencies, potential for integration tests instead of unit tests.

**Fix Required**:
- Review all module tests to ensure external tools (nmap, subfinder, nuclei) are mocked
- Use `unittest.mock` or `pytest-mock` consistently
- Update fixtures with better mock data

#### 13. Test Data Management (LOW)
**Status**: Good fixture structure but could be improved

**Issue**: Some test fixtures use hardcoded data that doesn't match real-world scenarios.

**Impact**: Tests may not catch edge cases.

**Fix Required**:
- Add diverse test data sets (edge cases, empty inputs, malformed data)
- Add stress test data (large inputs, unicode characters)
- Add fixture generators for dynamic test data

### Code Quality Issues

#### 14. Magic Numbers and Strings (MEDIUM)
**Files**: All modules

**Issue**: Hardcoded values scattered throughout codebase.

**Examples**:
```python
# Multiple occurrences
timeout=30  # What is 30?
timeout=120  # What is 120?
workers=10  # Why 10?
limit=20  # Why 20?
```

**Status**: PARTIALLY FIXED - `asm/timeouts.py` created with timeout constants.

**Fix Required**:
- Use timeout constants from `timeouts.py` consistently
- Extract remaining magic numbers to named constants
- Create constants file for: thread pool sizes, result limits, retry counts

**Estimated Impact**: Replace ~50 magic values across codebase

#### 15. Print Statements Instead of Logging (MEDIUM)
**Files**: All modules, CLI

**Issue**: Using `print()` for output and error messages instead of structured logging.

```python
# Example from multiple files
print(f"Error: {error}")
print(f"[!] {source} failed: {e}")
```

**Impact**: No structured logs, difficult to debug in production, no log levels, no timestamps.

**Status**: PARTIALLY FIXED - `error_handler.py` provides logging framework but not consistently used.

**Fix Required**:
- Replace all `print()` statements with `logger` calls
- Use appropriate log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Use Rich console for user-facing output only
- Preserve existing output format but add logging

**Estimated Impact**: Replace ~80 print statements

#### 16. Poor Variable Naming (LOW)
**Files**: Multiple modules

**Issue**: Unclear variable names that don't describe their purpose.

**Examples**:
```python
# Various occurrences
f = result  # What is f?
d = data     # What is d?
r = response  # What is r?
```

**Impact**: Reduced code readability, harder maintenance.

**Fix Required**:
- Rename single-letter variables to descriptive names
- Use meaningful variable names that describe content/purpose
- Follow PEP 8 naming conventions

#### 17. Missing Docstrings (LOW)
**Files**: All modules

**Issue**: Some functions and classes lack comprehensive docstrings.

**Impact**: Poor IDE documentation, difficult API usage.

**Fix Required**:
- Add module-level docstrings explaining purpose
- Add function docstrings with Args, Returns, Raises
- Add class docstrings
- Document all public APIs

**Estimated Effort**: 4-6 hours

### Dependency and Security Issues

#### 18. Outdated Dependencies (MEDIUM)
**File**: `requirements.txt`

**Status**: Dependencies appear current but should verify for security updates.

**Risk**: Known vulnerabilities in dependencies could be exploitable.

**Fix Required**:
- Run `pip-audit` or `safety` to check for known vulnerabilities
- Update dependencies with security advisories
- Pin specific versions in requirements.txt
- Set up automated dependency scanning in CI/CD

#### 19. External Tool Management (MEDIUM)
**Files**: `asm/modules/*.py`, `Dockerfile`

**Issue**: No validation that external tools (nmap, subfinder, nuclei, gau, httpx) are installed before use.

**Impact**: Runtime failures with confusing error messages.

**Fix Required**:
- Implement tool availability checks on module initialization
- Provide clear error messages with installation instructions
- Consider container pre-flight checks
- Document tool version requirements

**Example**:
```python
# Already implemented in ports.py:22-28
self.nmap_available = self._check_nmap()
```

**Fix Required**: Add similar checks to all modules that use external tools.

#### 20. No Rate Limiting (MEDIUM)
**Files**: All modules making HTTP/DNS requests

**Issue**: No rate limiting for API calls to external services.

**Impact**: Could trigger API rate limits, get IPs blocked, consume excessive bandwidth.

**Fix Required**:
- Implement rate limiter using `asyncio-throttle` (already in requirements.txt)
- Add per-host rate tracking
- Implement exponential backoff for failures
- Make rate limits configurable

**Example Implementation**:
```python
from asyncio_throttle import Throttler

throttler = Throttler(rate_limit=10, period=1)  # 10 requests per second

@throttler
async def make_request(url):
    # Rate-limited request
```

### Documentation Gaps

#### 21. Missing API Documentation (LOW)
**Status**: README provides high-level overview but lacks detailed API reference.

**Impact**: Difficult for contributors to understand module interfaces.

**Fix Required**:
- Create `docs/api/` directory with module-by-module API docs
- Document all public classes, methods, and their parameters
- Add usage examples for common tasks
- Document return types and error conditions

**Estimated Effort**: 8-12 hours

#### 22. Inconsistent Code Style (LOW)
**Status**: Most code follows PEP 8 but some inconsistencies exist.

**Issues**:
- Inconsistent docstring formatting (Google style vs NumPy style)
- Mixed single and double quotes
- Inconsistent line length (some >100 chars)

**Fix Required**:
- Configure pre-commit hooks for linting (black, flake8)
- Enforce consistent docstring style (Google style recommended)
- Set up `ruff` for fast Python linting
- Add line length enforcement

#### 23. No Architecture Decision Records (LOW)
**Status**: No ADRs (Architecture Decision Records) explaining key design choices.

**Impact**: Future maintainers may not understand why certain decisions were made.

**Fix Required**:
- Create `docs/adr/` directory
- Document key decisions: TinyDB vs PostgreSQL, external tools vs pure Python, etc.
- Record trade-offs and alternatives considered

**Estimated Effort**: 4-6 hours

---

## Prioritized Action Plan

### Phase 1: Critical Security Fixes (Week 1)

#### 1.1 Fix Command Injection (P0 - CRITICAL)
- [x] Audit all subprocess calls for command injection risks
- [x] Implement input sanitization for domain/port inputs
- [x] Add `shlex.quote()` for shell arguments
- [x] Create allowlist validator for ports and domains
- [x] Write tests for command injection prevention
- [x] Verify with security review

**Files**: `asm/modules/ports.py`, `asm/modules/subdomains.py`, `asm/modules/urls.py`

**Verification**: Run security scanning (bandit), manual review

#### 1.2 Fix Path Traversal (P0 - CRITICAL)
- [ ] Audit all file write operations for path traversal
- [ ] Add path validation utilities in `asm/core/utils.py` (new file)
- [ ] Use `Path.resolve()` to normalize paths
- [ ] Validate output paths are within allowed directories
- [ ] Write tests for path traversal prevention

**Files**: `asm/core/reporter.py`, `asm/__main__.py`

**Verification**: Run security scanning (bandit), manual review

#### 1.3 Secure Credential Management (P1 - HIGH)
- [ ] Add `config.yaml` to `.gitignore`
- [ ] Create `.env.example` template for environment variables
- [ ] Document credential storage best practices
- [ ] Add environment variable support in `Config` class
- [ ] Update README with credential management section

**Files**: `.gitignore`, `config.yaml`, `asm/core/config.py`, `README.md`

**Verification**: Manual review, ensure no credentials in git history

### Phase 2: Testing Infrastructure (Week 2-3)

#### 2.1 Add Module Unit Tests (P1 - HIGH)
- [ ] Create `tests/unit/test_subdomains.py` - Mock subfinder/submodule
- [ ] Create `tests/unit/test_ports.py` - Mock nmap
- [ ] Create `tests/unit/test_certificates.py` - Mock SSL/certificate checks
- [ ] Create `tests/unit/test_api_discovery.py` - Mock HTTP/API requests
- [ ] Create `tests/unit/test_technologies.py` - Mock httpx
- [ ] Create `tests/unit/test_dns_monitor.py` - Mock DNS queries
- [ ] Create `tests/unit/test_nuclei_scanner.py` - Mock nuclei
- [ ] Create `tests/unit/test_urls.py` - Mock GAU
- [ ] Create `tests/unit/test_takeover.py` - Mock takeover detection
- [ ] Create `tests/unit/test_emails.py` - Mock email enumeration

**Target**: 70%+ module coverage

**Verification**: Run `pytest --cov=asm --cov-report=html`, check coverage >70%

#### 2.2 Add Integration Tests (P2 - MEDIUM)
- [ ] Create `tests/integration/test_workflows.py` - End-to-end scan workflow
- [ ] Create `tests/integration/test_database.py` - Database persistence across restarts
- [ ] Create `tests/integration/test_notifications.py` - Notification delivery
- [ ] Add smoke test for common user workflows

**Verification**: All integration tests pass in CI

#### 2.3 Improve Test Fixtures (P2 - MEDIUM)
- [ ] Add diverse test data sets (edge cases, empty inputs, malformed data)
- [ ] Add fixture generators for dynamic test data
- [ ] Add stress test data (large inputs, unicode)
- [ ] Mock all external dependencies consistently

**Verification**: Tests cover edge cases identified in code review

### Phase 3: Code Quality Improvements (Week 4-5)

#### 3.1 Refactor Database Class (P2 - MEDIUM)
- [ ] Create `asm/repositories/` directory
- [ ] Create `asm/repositories/base_repository.py` - Base repository with common ops
- [ ] Create `asm/repositories/subdomain_repository.py`
- [ ] Create `asm/repositories/port_repository.py`
- [ ] Create `asm/repositories/certificate_repository.py`
- [ ] Create `asm/repositories/finding_repository.py`
- [ ] Create `asm/repositories/url_repository.py`
- [ ] Update `Database` class to use repositories
- [ ] Update all modules to use new repositories
- [ ] Migrate existing tests to new structure

**Goal**: Reduce database.py from 631 to ~100 lines

**Verification**: All tests pass, no data loss in migration

#### 3.2 Replace Print Statements (P2 - MEDIUM)
- [ ] Replace `print()` with `logger.debug()` for diagnostics
- [ ] Replace `print()` with `logger.info()` for informational messages
- [ ] Replace `print()` with `logger.warning()` for warnings
- [ ] Replace `print()` with `logger.error()` for errors
- [ ] Keep Rich console for user-facing CLI output only
- [ ] Add context to all log messages

**Goal**: Zero `print()` statements in production code (except CLI output via Rich)

**Verification**: Run test suite, check logs have proper structure

#### 3.3 Standardize Error Handling (P2 - MEDIUM)
- [ ] Use `@handle_errors` decorator on all public module methods
- [ ] Ensure all exceptions logged with context
- [ ] Remove bare `except:` clauses
- [ ] Add specific exception types where possible
- [ ] Create custom exception types for common errors

**Verification**: Run tests, check error handling coverage

#### 3.4 Add Comprehensive Type Annotations (P2 - MEDIUM)
- [ ] Add type hints to all public methods in modules
- [ ] Create `asm/types.py` for shared type definitions
- [ ] Use `TypedDict` for complex return types
- [ ] Add `->` return type annotations to all functions
- [ ] Run mypy type checking

**Goal**: 90%+ type annotation coverage

**Verification**: `mypy asm/` passes with no errors

#### 3.5 Extract Code Duplication (P3 - MEDIUM)
- [ ] Extract target resolution helper in CLI utilities
- [ ] Create HTTP client wrapper for common request patterns
- [ ] Extract notification payload builders to separate module
- [ ] Remove duplicate code from CLI commands
- [ ] Remove duplicate code from modules

**Goal**: Reduce code duplication by 30%+

**Verification**: Manual code review, check for duplicate patterns

### Phase 4: Configuration and Documentation (Week 6)

#### 4.1 Complete Constants Extraction (P2 - MEDIUM)
- [ ] Extract thread pool size constants to `asm/constants/timeouts.py`
- [ ] Extract result limit constants
- [ ] Extract retry count constants
- [ ] Use all timeout constants consistently across codebase
- [ ] Replace all remaining magic numbers

**Verification**: No hardcoded numbers remain (except test data)

#### 4.2 Improve API Documentation (P3 - LOW)
- [ ] Create `docs/api/README.md` - API overview
- [ ] Document each module: classes, methods, parameters, return types
- [ ] Add usage examples for common tasks
- [ ] Document error conditions and handling
- [ ] Update developer guide with API reference

**Verification**: All public APIs documented

#### 4.3 Add Architecture Decision Records (P3 - LOW)
- [ ] Create `docs/adr/` directory
- [ ] Document TinyDB vs PostgreSQL decision
- [ ] Document external tools vs pure Python decision
- [ ] Document Docker networking choice
- [ ] Document test coverage targets

**Verification**: All key architectural decisions documented

#### 4.4 Setup Pre-commit Hooks (P3 - LOW)
- [ ] Install `black` for code formatting
- [ ] Install `ruff` for fast Python linting
- [ ] Install `mypy` for type checking
- [ ] Create `.pre-commit-config.yaml`
- [ ] Add pre-commit installation to developer guide

**Verification**: Pre-commit hooks run on all commits

### Phase 5: Dependency and Performance (Week 7)

#### 5.1 Audit and Update Dependencies (P2 - MEDIUM)
- [ ] Run `pip-audit` on requirements.txt
- [ ] Run `safety` check for known vulnerabilities
- [ ] Update dependencies with security advisories
- [ ] Pin specific versions in requirements.txt
- [ ] Set up automated dependency scanning in CI/CD

**Verification**: No known vulnerabilities, automated scanning configured

#### 5.2 Implement Rate Limiting (P2 - MEDIUM)
- [ ] Implement rate limiter using `asyncio-throttle`
- [ ] Add per-host rate tracking
- [ ] Implement exponential backoff for failures
- [ ] Make rate limits configurable in Config
- [ ] Add rate limiting to all HTTP/DNS request modules

**Verification**: No rate limit violations in tests

#### 5.3 External Tool Availability Checks (P2 - MEDIUM)
- [ ] Implement tool availability checks for: nuclei, gau, httpx
- [ ] Provide clear error messages with installation instructions
- [ ] Add container pre-flight checks in Dockerfile
- [ ] Document tool version requirements

**Verification**: All tools checked before use, clear error messages

#### 5.4 Performance Optimization (P3 - LOW)
- [ ] Profile database operations with cProfile
- [ ] Optimize slow database queries
- [ ] Add database indexes if needed (TinyDB doesn't support indexes)
- [ ] Optimize concurrent operations (thread pool tuning)
- [ ] Add caching for repeated operations

**Verification**: Performance benchmarks show improvement

### Phase 6: Advanced Features (Week 8+)

#### 6.1 Add Integration Test Coverage (P3 - LOW)
- [ ] Create test database backup/restore
- [ ] Test data migration between versions
- [ ] Test concurrent scan operations
- [ ] Test notification delivery end-to-end

#### 6.2 Continuous Integration Setup (P3 - LOW)
- [ ] Create `.github/workflows/ci.yml`
- [ ] Configure automated testing on push/PR
- [ ] Configure automated security scanning
- [ ] Configure code coverage reporting
- [ ] Configure release automation

#### 6.3 Enhanced Reporting (P4 - LOW)
- [ ] Add PDF report format
- [ ] Add CSV export for findings
- [ ] Add graphical charts to reports
- [ ] Add trend analysis (changes over time)
- [ ] Add custom report templates

---

## Verification Steps

### Security Verification
```bash
# Run security scanning
pip install bandit
bandit -r asm/ -f json -o security-report.json

# Check for SQL injection vulnerabilities
# (Manual code review already covered)

# Check for hardcoded credentials
grep -r "password\|secret\|api_key" --include="*.py" asm/ | grep -v "config.yaml"
```

### Code Quality Verification
```bash
# Run type checking
pip install mypy
mypy asm/

# Run linting
pip install ruff
ruff check asm/

# Run formatter check
pip install black
black --check asm/

# Run tests with coverage
pytest tests/ --cov=asm --cov-report=html --cov-report=term

# Verify coverage meets targets (70%+ for modules)
```

### Functionality Verification
```bash
# Build Docker image
docker build -t asm-tool .

# Run smoke tests
docker run --rm asm-tool scan example.com
docker run --rm asm-tool status
docker run --rm asm-tool report

# Run full test suite
docker run --rm -v $(pwd)/tests:/app/tests asm-tool pytest tests/ -v

# Test each module individually
docker run --rm asm-tool discover example.com
docker run --rm asm-tool portscan example.com
docker run --rm asm-tool certificates example.com
docker run --rm asm-tool vulnscan example.com
```

### Performance Verification
```bash
# Profile database operations
python -m cProfile -o profile.stats -m asm.core.database

# Test with large datasets
python -m asm discover example.com
python -m asm portscan --all-known

# Monitor resource usage
docker stats asm-tool
```

---

## Risk Assessment

### High-Risk Items
1. **Command Injection Vulnerabilities** - P0 - Must fix immediately
2. **Path Traversal** - P0 - Must fix immediately
3. **Credential Exposure in Git** - P1 - Fix within 1 week

### Medium-Risk Items
4. **Insecure HTTP Requests** - P2 - Fix within 2 weeks
5. **Missing Input Validation** - P2 - Fix within 2 weeks
6. **God Class (Database)** - P2 - Fix within 4 weeks
7. **Incomplete Test Coverage** - P2 - Fix within 4 weeks

### Low-Risk Items
8. **Code Duplication** - P3 - Fix within 6 weeks
9. **Magic Numbers** - P3 - Fix within 6 weeks
10. **Print Statements** - P3 - Fix within 6 weeks

---

## Estimated Timeline

| Phase | Duration | Priority | Effort |
|-------|----------|----------|--------|
| Critical Security Fixes | 1 week | P0-P1 | 40 hours |
| Testing Infrastructure | 2 weeks | P1-P2 | 60 hours |
| Code Quality Improvements | 2 weeks | P2 | 50 hours |
| Configuration & Documentation | 1 week | P2-P3 | 30 hours |
| Dependency & Performance | 1 week | P2-P3 | 35 hours |
| Advanced Features | Ongoing | P3-P4 | 40 hours |

**Total Estimated Effort**: ~255 hours (32 days)

---

## Success Metrics

### Security Metrics
- [ ] Zero command injection vulnerabilities
- [ ] Zero path traversal vulnerabilities
- [ ] No credentials in git history
- [ ] Security scan passes (bandit score A)

### Code Quality Metrics
- [ ] Test coverage >= 70% (modules)
- [ ] Type annotation coverage >= 90%
- [ ] Mypy passes with zero errors
- [ ] Ruff passes with zero warnings
- [ ] Code duplication reduced by 30%

### Functionality Metrics
- [ ] All existing tests pass (0 failures)
- [ ] All new tests pass
- [ ] Smoke tests for all workflows pass
- [ ] No observable behavior changes
- [ ] All CLI commands work identically

### Documentation Metrics
- [ ] All public APIs documented
- [ ] All architecture decisions recorded
- [ ] README updated with security sections
- [ ] Developer guide complete

---

## Dependencies

### Python Dependencies (from requirements.txt)
```
click>=8.1.0              # CLI framework
rich>=13.0.0              # Terminal output
pyyaml>=6.0.0              # Configuration
dnspython>=2.4.0           # DNS resolution
requests>=2.31.0            # HTTP client
aiohttp>=3.9.0             # Async HTTP
aiodns>=3.1.0             # Async DNS
tinydb>=4.8.0              # Database
python-dateutil>=2.8.0       # Date handling
jinja2>=3.1.0              # Templates
cryptography>=41.0.0         # TLS certificates
pyOpenSSL>=23.3.0          # OpenSSL bindings
slack-sdk>=3.23.0           # Slack notifications
apprise>=1.6.0              # Multi-channel notifications
asyncio-throttle>=1.0.0     # Rate limiting
shodan>=1.30.0             # Shodan integration
python-whois>=0.8.0         # WHOIS lookups
```

### External Tools (from Dockerfile)
```
nmap          # Port scanning
subfinder     # Subdomain enumeration
assetfinder   # Subdomain enumeration
httpx         # HTTP probing
nuclei        # Vulnerability scanning
gau           # URL enumeration
```

---

## Unknowns and Open Questions

### Architecture
1. **Database Scaling**: TinyDB works for current scale but has limits. At what data volume should we consider migration to PostgreSQL/SQLite?
   - **Recommendation**: Monitor performance, create migration plan for >10,000 records per table

2. **Async vs Sync**: Most code is synchronous. Should we migrate to async for better performance?
   - **Recommendation**: Keep synchronous for simplicity unless performance testing shows bottlenecks

### Security
3. **SSL Verification**: Why is `verify=False` used everywhere?
   - **Recommendation**: Document this as intentional (self-signed certs common during scanning), make it configurable

4. **Rate Limiting**: What are appropriate default rate limits for various APIs?
   - **Recommendation**: Start with conservative limits (10 req/s), allow per-service configuration

### Testing
5. **External Tool Testing**: Should we integrate with external tools or mock them completely?
   - **Recommendation**: Keep external tool integration (it's a feature), but mock thoroughly in tests

### Deployment
6. **Production Deployment**: What's the recommended production deployment strategy?
   - **Recommendation**: Use Docker Compose with scheduler profile, configure cron on host machine

---

## Recommendations

### Immediate Actions (This Week)
1. **Fix command injection vulnerabilities** - P0 critical security issue
2. **Fix path traversal vulnerabilities** - P0 critical security issue
3. **Secure credential management** - Add .gitignore and env var support
4. **Set up pre-commit hooks** - Enforce code quality standards

### Short-term Actions (Next 4 Weeks)
5. **Improve test coverage** - Add unit tests for all 10 scanning modules
6. **Refactor database class** - Extract repository pattern
7. **Standardize error handling** - Use centralized error handler
8. **Replace print statements** - Use structured logging

### Medium-term Actions (Next 8 Weeks)
9. **Add comprehensive type annotations** - Improve type safety
10. **Implement rate limiting** - Protect against API rate limits
11. **Improve API documentation** - Document all public APIs
12. **Setup CI/CD pipeline** - Automated testing and deployment

### Long-term Actions (Future)
13. **Consider database migration** - Evaluate TinyDB vs alternatives for scale
14. **Add performance monitoring** - Track database and scan performance
15. **Enhanced reporting** - Add more report formats and visualizations
16. **Plugin architecture** - Allow third-party scanning modules

---

## Conclusion

The ASM Tool codebase is well-architected with a clear separation of concerns and comprehensive feature set. However, several **critical security vulnerabilities** require immediate attention:

1. **Command injection** in external tool calls
2. **Path traversal** in file operations
3. **Credential exposure** in version control

Beyond security issues, the codebase suffers from **technical debt** that impacts maintainability:
- God class (Database) with 13 responsibilities
- Incomplete test coverage (16% for modules vs 70% target)
- Inconsistent error handling and logging
- Code duplication and magic numbers

The prioritized plan addresses these issues systematically, starting with critical security fixes and moving to quality improvements. The estimated timeline of 32 weeks (255 hours) is realistic for a single developer working part-time or a team working full-time.

---

**Document Version**: 1.0
**Last Updated**: 2026-01-04
**Author**: Sisyphus - Codebase Analysis Agent
