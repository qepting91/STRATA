# STRATA Makefile.
#
# NOTE: GNU Make may not be installed on Windows out of the box (verify
# with `make --version`). If it is missing, the `uv run <cmd>` invocations
# below are the primary supported interface — see README.md. This
# Makefile is a convenience wrapper, not a requirement.

.PHONY: test collect build hunt report

test:
	uv run pytest -v

collect:
	uv run strata collect --source all

# Later-week targets (see strata-engineering-spec.md build plan). Not
# implemented yet; these are intentionally no-ops rather than silently
# missing targets.
build:
	@echo "not implemented (Week 3+)"

hunt:
	@echo "not implemented (Week 4+)"

report:
	@echo "not implemented (Week 4+)"

