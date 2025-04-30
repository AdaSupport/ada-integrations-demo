.PHONY: build run clean

build:
	@echo "Setting up Python virtual environment..."
	python -m venv .venv
	@echo "Activating virtual environment..."
	. .venv/bin/activate && \
	pip install --upgrade pip && \
	pip install -r requirements.txt
	@echo "Build complete! Activate the environment with: source .venv/bin/activate"

run:
	@echo "Starting the application..."
	. .venv/bin/activate && python run.py

clean:
	@echo "Cleaning up..."
	rm -rf .venv
	rm -rf __pycache__
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type f -name "*.pyc" -delete

setup-env:
	@if [ ! -f .env ]; then \
		echo "Creating .env file from .env.example..."; \
		cp .env.example .env; \
		echo "Please update .env with your configuration values"; \
	else \
		echo ".env file already exists"; \
	fi 