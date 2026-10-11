GOLIB ?= golib

.PHONY: check ci cohesion fast-check inventory repository-check

check:
	$(GOLIB) check --all

# Requires the process-improvement verifier's local-docs and secrets commands.
# CI retains its current contract until that verifier is publicly qualified.
fast-check:
	$(GOLIB) config validate
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) specification check
	$(GOLIB) docs check --local
	$(GOLIB) secrets check

ci:
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) specification check --online
	$(GOLIB) check --all

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check
