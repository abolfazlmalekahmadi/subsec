.DEFAULT_GOAL := help
SHELL := /bin/bash
ML_DIR := ml/anomaly_service

.PHONY: help up down status validate logs topics ml-install ml-test ml-lint lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

up: ## Bring up the dev stack with health checks
	./scripts/deploy.sh up

down: ## Tear down the dev stack
	./scripts/deploy.sh down

status: ## Show health of each service
	./scripts/deploy.sh status

validate: ## Fire synthetic events and verify the pipeline
	./scripts/deploy.sh validate

logs: ## Tail compose logs
	docker compose logs -f --tail=100

topics: ## Create Kafka topics
	./kafka/topics.sh

ml-install: ## Install ML service deps into a venv
	cd $(ML_DIR) && python3 -m venv .venv && \
		.venv/bin/pip install -U pip && \
		.venv/bin/pip install -r requirements.txt -r requirements-dev.txt

ml-test: ## Run ML service unit tests with coverage
	cd $(ML_DIR) && .venv/bin/pytest -q --cov=. --cov-report=term-missing

ml-lint: ## Lint the ML service with ruff
	cd $(ML_DIR) && .venv/bin/ruff check .

lint: ## Shellcheck all shell scripts
	@find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 shellcheck -x
