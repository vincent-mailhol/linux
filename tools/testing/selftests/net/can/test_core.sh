#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

export CANIF=${CANIF:-"vcan0"}
BITRATE=${BITRATE:-500000}
DBITRATE=${DBITRATE:-2000000}
FD=${FD:1}

setup_if()
{
	if [[ $CANIF == vcan* ]]; then
		ip link add name $CANIF type vcan || exit $ksft_skip
		if [[ $FD == 1 ]]; then
			ip link set $CANIF mtu 72 || exit $ksft_skip
		fi
	elif [[ $FD == 1 ]]; then
		ip link set dev $CANIF type can bitrate $BITRATE dbitrate $DBITRATE || exit $ksft_skip
	else
		ip link set dev $CANIF type can bitrate $BITRATE || exit $ksft_skip
	fi
	ip link set dev $CANIF up
	pwd
}

cleanup_if()
{
	ip link set dev $CANIF down
	if [[ $CANIF == vcan* ]]; then
		ip link delete $CANIF
	fi
}
