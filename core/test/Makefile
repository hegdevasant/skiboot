# Stupid makefile, but this doesn't need cross-building.
CFLAGS := -Wall -g -fprofile-arcs -ftest-coverage -I../../include -I../.. -I../../libfdt
TEST_SRC := $(wildcard run*.c)
TESTS := $(TEST_SRC:.c=)

test: $(TESTS)
	set -e; for t in $(TESTS); do echo -n $$t...; valgrind -q --leak-check=yes --error-exitcode=99 ./$$t; echo PASSED; done

coverage: test
	gcov $(TEST_SRC)

clean:
	$(RM) -f $(TESTS) *.gcno *.gcov *.gcda
