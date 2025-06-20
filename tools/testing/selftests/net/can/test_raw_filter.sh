#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ALL_TESTS="
	test_raw_filter
"

net_dir=$(dirname $0)/..
source $net_dir/lib.sh
source test_core.sh

setup()
{
	setup_if
}

cleanup()
{
        cleanup_if
}

test_raw_filter()
{
	./test_raw_filter
	check_err $?
	log_test "test_raw_filter"
}

trap cleanup EXIT
setup

tests_run

exit $EXIT_STATUS
