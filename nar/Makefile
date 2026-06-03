.PHONY: gen bin test

gen:
	python gen.py

bin:
	$(MAKE) -C ../oracles/nar bin

test: bin
	python ../oracles/run_test.py --table ../oracles/nar/bin/* .
