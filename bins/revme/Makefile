PACKAGE_VERSION=0.3.1

.PHONY: clone_state_tests
clone_state_tests:
	if [ ! -d tests ]; then \
  		git clone https://github.com/ethereum/tests; \
  	else \
  		cd tests; git fetch --all; git checkout 1c23e3c27ac53b794de0844d2d5e19cd2495b9d8; \
  	fi

.PHONY: run_state_tests
run_state_tests:
	cargo run -p revme@$(PACKAGE_VERSION) statetest tests/GeneralStateTests #-s

.PHONY: command_help
command_help:
	cargo run -p revme@$(PACKAGE_VERSION) -h
