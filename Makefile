# -- General
SHELL := /bin/bash

# -- Docker
# Get the current user ID to use for docker run and docker exec commands
DOCKER_UID           = $(shell id -u)
DOCKER_GID           = $(shell id -g)
DOCKER_USER          = $(DOCKER_UID):$(DOCKER_GID)
DOCKER_IMAGE_NAME    = fundocker/obc
DOCKER_IMAGE_TAG     = latest
DOCKER_IMAGE         = $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
DOCKER               = docker
DOCKER_RUN           = $(DOCKER) run --rm --user $(DOCKER_USER) --mount type=bind,src="$(PWD)",dst=/app
DOCKER_RUN_OBC       = $(DOCKER_RUN) $(DOCKER_IMAGE)

# ==============================================================================
# RULES

default: help

bootstrap: ## bootstrap the project for development
bootstrap: \
  build \
	dev
.PHONY: bootstrap

build: ## build the app container
	$(DOCKER) build -t $(DOCKER_IMAGE) .
.PHONY: build

dev: ## perform editable install from mounted project sources
	$(DOCKER_RUN_OBC) pip install -e ".[dev]"
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
	@$(DOCKER_RUN_OBC) black src/obc tests
.PHONY: lint-black

lint-flake8: ## lint back-end python sources with flake8
	@echo 'lint:flake8 started…'
	@$(DOCKER_RUN_OBC) flake8
.PHONY: lint-flake8

lint-isort: ## automatically re-arrange python imports in back-end code base
	@echo 'lint:isort started…'
	@$(DOCKER_RUN_OBC) isort --atomic .
.PHONY: lint-isort

lint-pylint: ## lint back-end python sources with pylint
	@echo 'lint:pylint started…'
	@$(DOCKER_RUN) -e PYLINTHOME=/app/.pylint.d $(DOCKER_IMAGE) pylint src/obc tests
.PHONY: lint-pylint

lint-bandit: ## lint back-end python sources with bandit
	@echo 'lint:bandit started…'
	@$(DOCKER_RUN_OBC) bandit -qr src/obc
.PHONY: lint-bandit

lint-pydocstyle: ## lint Python docstrings with pydocstyle
	@echo 'lint:pydocstyle started…'
	@$(DOCKER_RUN_OBC) pydocstyle
.PHONY: lint-pydocstyle

test: ## run back-end tests
	bin/pytest
.PHONY: test

# -- Misc
help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help
