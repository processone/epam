REBAR ?= rebar

all: src

src:
	$(REBAR) compile

clean:
	$(REBAR) clean

.PHONY: clean src
