.PHONY: test gen

test:
	uvx pytest

gen:
	$(MAKE) -C deflate gen
	$(MAKE) -C zip gen
	$(MAKE) -C tar gen
	$(MAKE) -C zar gen
	$(MAKE) -C zstd gen
	$(MAKE) -C nar gen
