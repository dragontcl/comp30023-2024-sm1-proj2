EXE=fetchmail

$(EXE): main.c
	cc -Wall -o $(EXE) $<

# Rust
# $(EXE): src/*.rs vendor
# 	cargo build --frozen --offline --release
# 	cp target/release/$(EXE) .

# vendor:
# 	if [ ! -d "vendor/" ]; then \
# 		cargo vendor --locked; \
# 	fi

format:
	clang-format -style=file -i *.c
