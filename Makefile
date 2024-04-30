.PHONY: test
test:
	cd bins/revme; $(MAKE) clone_state_tests; $(MAKE) run_state_tests
