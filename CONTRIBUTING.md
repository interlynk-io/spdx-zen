# Contributing to SPDX Zen

We love your input! We want to make contributing to SPDX Zen as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Development Setup

### Prerequisites

- Go 1.21 or higher
- golangci-lint (for linting)
- make (optional, for using Makefile)

### Getting Started

1. Clone your fork:
```bash
git clone https://github.com/YOUR_USERNAME/spdx-zen.git
cd spdx-zen
```

2. Install dependencies:
```bash
go mod download
```

3. Run tests:
```bash
go test -v ./...
```

4. Run linting:
```bash
golangci-lint run
```

### Building

Build the spdx-gen tool:
```bash
go build -o bin/spdx-gen ./cmd/spdx-gen
```

## Code Style

- We use `gofmt` for formatting Go code
- Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Run `golangci-lint` before submitting PRs
- Keep functions focused and small
- Write clear, self-documenting code with meaningful variable names

## Testing

- Write unit tests for new functionality
- Maintain or improve code coverage
- Test files should be placed in the same package as the code they test
- Use table-driven tests where appropriate
- Run the full test suite before submitting PRs:
  ```bash
  go test -v -race ./...
  ```

## Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable.
2. Update the documentation with any new features or changes.
3. The PR title should follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for test changes
   - `refactor:` for code refactoring
   - `chore:` for maintenance tasks
4. Include relevant issue numbers in the PR description.
5. PRs require at least one review approval before merging.

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Examples:
- `feat(parse): add support for SPDX 3.1 format`
- `fix(stream): handle empty document gracefully`
- `docs: update installation instructions`

## Adding Support for New SPDX Versions

When a new SPDX specification version is released:

1. Download the new model specification file
2. Generate types using spdx-gen:
   ```bash
   go run cmd/spdx-gen/main.go \
     -spec spdx-3.X.X-model.json-ld \
     -out ./model/v3.X.X \
     -pkg spdx \
     -version 3.X.X
   ```
3. Update `SupportedVersions` in `spdx/version.go`
4. Add tests for the new version
5. Update documentation

## Reporting Bugs

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/interlynk-io/spdx-zen/issues/new).

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Feature Requests

We love feature requests! Please [open an issue](https://github.com/interlynk-io/spdx-zen/issues/new) and describe:

- The use case for the feature
- Proposed implementation approach (if you have one)
- Any alternatives you've considered

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## References

This document was adapted from the open-source contribution guidelines template by [Briandk](https://gist.github.com/briandk/3d2e8b3ec8daf5a27a62).

## Questions?

Feel free to open an issue with your question or contact the maintainers directly.