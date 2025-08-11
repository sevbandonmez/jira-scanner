.PHONY: help install test run clean docker-build docker-run

# Default target
help:
	@echo "Available commands:"
	@echo "  install      - Install dependencies"
	@echo "  test         - Run basic tests"
	@echo "  run          - Run the scanner with help"
	@echo "  clean        - Clean up generated files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run scanner in Docker"
	@echo "  scan-single  - Scan a single URL (usage: make scan-single URL=https://example.com)"
	@echo "  scan-batch   - Scan multiple URLs from file (usage: make scan-batch FILE=urls.txt)"

# Install dependencies
install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "Installation complete!"

# Run basic tests
test:
	@echo "Running basic tests..."
	python3 -c "import requests, urllib3, json, argparse; print('All imports successful')"
	@echo "Tests passed!"

# Run the scanner with help
run:
	@echo "Running Jira Security Scanner..."
	python3 jira-scanner.py --help

# Clean up generated files
clean:
	@echo "Cleaning up..."
	rm -rf output/
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf .pytest_cache/
	@echo "Cleanup complete!"

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t jira-security-scanner .
	@echo "Docker image built successfully!"

# Run scanner in Docker
docker-run:
	@echo "Running scanner in Docker..."
	docker run --rm -v $(PWD)/output:/app/output jira-security-scanner --help

# Scan a single URL
scan-single:
	@if [ -z "$(URL)" ]; then \
		echo "Error: URL parameter is required"; \
		echo "Usage: make scan-single URL=https://jira.example.com"; \
		exit 1; \
	fi
	@echo "Scanning single URL: $(URL)"
	python3 jira-scanner.py -u $(URL)

# Scan multiple URLs from file
scan-batch:
	@if [ -z "$(FILE)" ]; then \
		echo "Error: FILE parameter is required"; \
		echo "Usage: make scan-batch FILE=urls.txt"; \
		exit 1; \
	fi
	@if [ ! -f "$(FILE)" ]; then \
		echo "Error: File $(FILE) not found"; \
		exit 1; \
	fi
	@echo "Scanning URLs from file: $(FILE)"
	python3 jira-scanner.py -f $(FILE)

# Install development dependencies
install-dev:
	@echo "Installing development dependencies..."
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8
	@echo "Development dependencies installed!"

# Format code
format:
	@echo "Formatting code..."
	black jira-scanner.py
	@echo "Code formatting complete!"

# Lint code
lint:
	@echo "Linting code..."
	flake8 jira-scanner.py
	@echo "Linting complete!"

# Security scan with Docker
docker-scan-single:
	@if [ -z "$(URL)" ]; then \
		echo "Error: URL parameter is required"; \
		echo "Usage: make docker-scan-single URL=https://jira.example.com"; \
		exit 1; \
	fi
	@echo "Scanning single URL with Docker: $(URL)"
	docker run --rm -v $(PWD)/output:/app/output jira-security-scanner -u $(URL)

# Security scan batch with Docker
docker-scan-batch:
	@if [ -z "$(FILE)" ]; then \
		echo "Error: FILE parameter is required"; \
		echo "Usage: make docker-scan-batch FILE=urls.txt"; \
		exit 1; \
	fi
	@if [ ! -f "$(FILE)" ]; then \
		echo "Error: File $(FILE) not found"; \
		exit 1; \
	fi
	@echo "Scanning URLs from file with Docker: $(FILE)"
	docker run --rm -v $(PWD)/output:/app/output -v $(PWD)/$(FILE):/app/$(FILE):ro jira-security-scanner -f $(FILE)
