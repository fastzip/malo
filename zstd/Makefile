.PHONY: gen bin test

gen:
	python gen.py

bin:
	$(MAKE) -C ../oracles/zstd bin

test: bin
	python ../oracles/run_test.py --table ../oracles/zstd/bin/* .
