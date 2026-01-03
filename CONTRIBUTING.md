# Contributing to ASM Tool

Thank you for your interest in contributing to the ASM Tool!

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/asm-tool.git
   cd asm-tool
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run tests**
   ```bash
   pytest tests/
   ```

## Code Style Guidelines

- **PEP 8 Compliant**: Follow Python style guide
- **Type Hints**: Use type annotations for all public methods
- **Docstrings**: Add docstrings for all public classes and functions
- **Error Handling**: Use proper exception handling with context
- **Constants**: Extract magic values to constants files

## Running Tests

Before submitting a PR, ensure:

1. **All tests pass**
   ```bash
   pytest tests/
   ```

2. **Coverage is maintained**
   ```bash
   pytest tests/ --cov=asm --cov-report=term
   ```
   Current target: 70%+ for modules

3. **No deprecation warnings**
   Ensure no deprecated API usage

## Submitting Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following style guidelines
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure all tests pass

3. **Commit with clear messages**
   ```bash
   git commit -m "feat: add new scanner module"
   ```

   Use conventional commit format:
   - `feat:` new feature
   - `fix:` bug fix
   - `refactor:` code improvement
   - `docs:` documentation update
   - `test:` test changes
   - `chore:` maintenance tasks

4. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   gh pr create
   ```

## Project Structure

```
asm-tool/
├── asm/
│   ├── __init__.py
│   ├── __main__.py          # CLI entry point
│   ├── core/
│   │   ├── config.py        # Configuration management
│   │   ├── database.py      # TinyDB persistence
│   │   ├── notifier.py      # Slack/email alerts
│   │   ├── reporter.py      # Report generation
│   │   └── scheduler.py     # Cron scheduling
│   ├── constants/
│   │   ├── __init__.py
│   │   ├── api_paths.py
│   │   └── timeouts.py
│   └── modules/
│       ├── subdomains.py    # Subdomain enumeration
│       ├── ports.py         # Port scanning
│       ├── certificates.py  # SSL/TLS monitoring
│       ├── technologies.py  # Tech fingerprinting
│       ├── dns_monitor.py   # DNS record tracking
│       ├── nuclei_scanner.py # Vulnerability scanning
│       ├── urls.py          # URL enumeration
│       ├── takeover.py      # Subdomain takeover detection
│       ├── api_discovery.py # API endpoint discovery
│       └── emails.py        # Email enumeration
├── tests/
│   ├── fixtures.py           # Test data and utilities
│   └── unit/              # Unit tests for core modules
├── data/                   # Persistent data (asm.db)
├── reports/                # Generated reports
├── Dockerfile              # Container definition
├── docker-compose.yaml      # Docker orchestration
├── requirements.txt         # Python dependencies
├── config.example.yaml     # Example configuration
├── pytest.ini              # Test configuration
├── README.md               # Project documentation
├── REFACTOR_PLAN.md        # Refactoring roadmap
└── CONTRIBUTING.md          # This file
```

## Testing Strategy

### Unit Tests
- Located in `tests/unit/`
- Mock external dependencies (nmap, subfinder, nuclei, etc.)
- Test core modules in isolation
- Current: 92 unit tests passing

### Integration Tests
- Test cross-module interactions
- Verify database operations
- Test end-to-end workflows

### Coverage Goals
- Maintain 70%+ coverage for core modules
- Focus on testing critical paths and edge cases

## Adding New Features

1. **Create new scanning module** in `asm/modules/`
2. **Add tests** for the new module in `tests/unit/`
3. **Update CLI** in `asm/__main__.py` to expose the new module
4. **Update database** schema if needed
5. **Update README.md** with usage examples

## Questions?

Feel free to open an issue for questions or discussion. We're happy to help!

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT).
