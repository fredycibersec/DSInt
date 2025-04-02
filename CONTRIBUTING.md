# Contributing to DSInt

Thank you for your interest in contributing to DSInt! This document provides guidelines and instructions for contributing to this project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Development Environment Setup](#development-environment-setup)
  - [Running Tests](#running-tests)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Coding Standards](#coding-standards)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Documentation](#documentation)
- [Communication Channels](#communication-channels)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [project maintainers].

## Getting Started

### Development Environment Setup

1. **Fork the repository**:
   - Fork the repository on GitHub by clicking the "Fork" button at the top right of the repository page.

2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/DSInt.git
   cd DSInt
   ```

3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/original-owner/DSInt.git
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Install development dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```

### Running Tests

Ensure that your changes don't break existing functionality by running tests:

```bash
python -m pytest
```

## How to Contribute

### Reporting Bugs

If you find a bug in the project, please create an issue using the bug report template and include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Your environment details (OS, Python version, etc.)

### Suggesting Enhancements

If you have ideas for enhancing the project, please create an issue using the feature request template and include:

- A clear and descriptive title
- Detailed description of the suggested enhancement
- Potential implementation approach if you have one
- Why this enhancement would be useful to most users

### Pull Requests

1. **Create a new branch** from the `main` branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit them with clear, descriptive commit messages.

3. **Update documentation** if necessary.

4. **Run tests** to ensure your changes don't break existing functionality.

5. **Push your changes** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** from your branch to the original repository's `main` branch.

7. **Follow the PR template** and provide all requested information.

8. **Address review comments** if requested by maintainers.

## Coding Standards

We follow PEP 8 standards for Python code. Please ensure your code adheres to these standards:

- Use 4 spaces for indentation (not tabs)
- Maximum line length of 79 characters for code and 72 for docstrings/comments
- Use meaningful variable and function names
- Include docstrings for all functions, classes, and modules
- Write clear comments where necessary

You can check your code with the following tools:
```bash
# Check style with flake8
flake8 .

# Format your code with black
black .
```

## Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- Consider starting the commit message with an applicable prefix:
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `style:` for formatting changes
  - `refactor:` for code refactoring
  - `test:` for adding tests
  - `chore:` for maintenance tasks

## Documentation

- Update the README.md if you change functionality
- Add or update docstrings for any functions or classes you add or modify
- If adding new functionality, consider adding examples of how to use it

## Communication Channels

- **GitHub Issues**: For bug reports, feature requests, and discussions related to specific aspects of the code
- **Discussions**: For general questions and broader discussions about the project
- **Slack/Discord**: [Link to chat platform] for real-time communication with maintainers and other contributors

## License

By contributing to DSInt, you agree that your contributions will be licensed under the project's [MIT License](./LICENSE).

Thank you for contributing to DSInt!

