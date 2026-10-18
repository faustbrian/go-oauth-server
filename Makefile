GOLIB ?= golib

.PHONY: check check-full ci cohesion fast-check planning-check inventory repository-check specification-check-online secrets-check

# Standalone checks retain whole-tree/history secret proof, including dirty work.
check ci fast-check:
	$(GOLIB) config validate
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) specification check
	$(GOLIB) docs check --local
	$(GOLIB) secrets check

# CI adds validated immutable-range secrets separately; this is not a complete gate.
planning-check:
	$(GOLIB) config validate
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) specification check
	$(GOLIB) docs check --local

check-full:
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) specification check --online
	$(GOLIB) check --all

specification-check-online:
	$(GOLIB) specification check --online

secrets-check:
	$(GOLIB) secrets check

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check
