# -- General
SHELL := /bin/bash

# -- Docker
# Get the current user ID to use for docker run and docker exec commands
DOCKER_UID           = $(shell id -u)
DOCKER_GID           = $(shell id -g)
DOCKER_USER          = $(DOCKER_UID):$(DOCKER_GID)
COMPOSE              = DOCKER_USER=$(DOCKER_USER) docker compose
COMPOSE_RUN          = $(COMPOSE) run --rm
COMPOSE_TEST_RUN     = $(COMPOSE_RUN)
COMPOSE_TEST_RUN_APP = $(COMPOSE_TEST_RUN) app


# -- OBC
OBC_IMAGE_NAME         ?= obc
OBC_IMAGE_TAG          ?= development


# ==============================================================================
# RULES

default: help

bootstrap: ## bootstrap the project for development
bootstrap: \
  build \
	dev
.PHONY: bootstrap

build: ## build the app container
build:
	OBC_IMAGE_NAME=$(OBC_IMAGE_NAME) \
	OBC_IMAGE_TAG=$(OBC_IMAGE_TAG) \
	  $(COMPOSE) build app
.PHONY: build

dev: ## perform editable install from mounted project sources
	DOCKER_USER=0 docker compose run --rm app pip install -e ".[dev]"
.PHONY: dev

# Nota bene: Black should come after isort just in case they don't agree...
lint: ## lint back-end python sources
lint: \
  lint-isort \
  lint-black \
  lint-flake8 \
  lint-pylint \
  lint-bandit \
  lint-pydocstyle
.PHONY: lint

lint-black: ## lint back-end python sources with black
	@echo 'lint:black started…'
	@$(COMPOSE_TEST_RUN_APP) black src/obc tests
.PHONY: lint-black

lint-flake8: ## lint back-end python sources with flake8
	@echo 'lint:flake8 started…'
	@$(COMPOSE_TEST_RUN_APP) flake8
.PHONY: lint-flake8

lint-isort: ## automatically re-arrange python imports in back-end code base
	@echo 'lint:isort started…'
	@$(COMPOSE_TEST_RUN_APP) isort --atomic .
.PHONY: lint-isort

lint-pylint: ## lint back-end python sources with pylint
	@echo 'lint:pylint started…'
	@$(COMPOSE_TEST_RUN_APP) pylint src/obc tests
.PHONY: lint-pylint

lint-bandit: ## lint back-end python sources with bandit
	@echo 'lint:bandit started…'
	@$(COMPOSE_TEST_RUN_APP) bandit -qr src/obc
.PHONY: lint-bandit

lint-pydocstyle: ## lint Python docstrings with pydocstyle
	@echo 'lint:pydocstyle started…'
	@$(COMPOSE_TEST_RUN_APP) pydocstyle
.PHONY: lint-pydocstyle

test: ## run back-end tests
	bin/pytest
.PHONY: test

# -- Misc
help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help
