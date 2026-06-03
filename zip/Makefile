.PHONY: gen bin test

gen:
	python gen.py
	python gen_manual.py

bin:
	$(MAKE) -C ../oracles/zip bin

test: bin
	python ../oracles/run_test.py --table ../oracles/zip/bin/* .
