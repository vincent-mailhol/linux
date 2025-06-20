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
	setcap 'cap_net_raw=ep' test_pf_packet
	setup_if
}

cleanup()
{
	cleanup_if
}

test_raw_filter()
{
	./test_pf_packet
	check_err $?
	log_test "test_raw_filter"
}

trap cleanup EXIT
setup

tests_run

exit $EXIT_STATUS
