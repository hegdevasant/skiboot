# Stupid makefile, but this doesn't need cross-building.
CFLAGS := -Wall -g -I../../include -I../.. -I../../libfdt
LDFLAGS := -fprofile-arcs -ftest-coverage
TEST_SRC := $(wildcard run*.c)
HELPERS := stubs.o
TESTS := $(TEST_SRC:.c=)

run-device: run-device.o stubs.o

test: $(TESTS)
	set -e; for t in $(TESTS); do echo -n $$t...; valgrind -q --leak-check=yes --error-exitcode=99 ./$$t; echo PASSED; done

coverage: test
	gcov $(TEST_SRC)

clean:
	$(RM) -f $(TESTS) *.gcno *.gcov *.gcda
