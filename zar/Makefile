.PHONY: gen test bin

gen:
	python gen.py

bin:
	$(MAKE) -C ../oracles/zar bin

test: bin
	python ../oracles/run_test.py --table ../oracles/zar/bin/* .
