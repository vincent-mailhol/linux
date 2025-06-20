// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * Copyright (c) 2011 Volkswagen Group Electronic Research
 * All rights reserved.
 * Copyright (c) 2025 Vincent Mailhol <mailhol@kernel.org>
 */

#include <linux/can.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../kselftest_harness.h"

char CANIF[IFNAMSIZ];

int can_pf_packet_send(int s, __u8 len)
{
	struct can_frame frame = {
		.can_id  = 0x123,
		.len = len,
		.data = { 0x11, 0x22, 0x33, 0x44 },
	};
	int nbytes;

	printf("Send CAN frame of len %u with PF_PACKET\n", len);
	nbytes = write(s, &frame, sizeof(frame));
	if (nbytes < 0) {
		fprintf(stderr, "%s: write: %s\n", __func__, strerror(errno));
		return 1;
	}
	if (nbytes != sizeof(frame)) {
		fprintf(stderr, "%s: write_len: %s\n",
			__func__, strerror(errno));
		return 1;
	}
	return 0;
}

int can_pf_packet_read(int s)
{
	struct can_frame frame;
	int nbytes;

	if ((nbytes = read(s, &frame, sizeof(frame))) < 0) {
		perror("read");
		return 1;
	} else if (nbytes < sizeof(frame)) {
		fprintf(stderr, "read: incomplete CAN frame\n");
		return 1;
	} else {
		if (frame.can_id & CAN_EFF_FLAG)
			printf("%8X  ", frame.can_id & CAN_EFF_MASK);
		else
			printf("%3X  ", frame.can_id & CAN_SFF_MASK);

		printf("[%d] ", frame.len);

		for (int i = 0; i < frame.len; i++) {
			printf("%02X ", frame.data[i]);
		}
		if (frame.can_id & CAN_RTR_FLAG)
			printf("remote request");
		printf("\n");
		fflush(stdout);
	}
	return 0;
}

int main(int argc, char **argv)
{
	char *ifname = getenv("CANIF");
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_CAN),
	};
	int s;

	if (!ifname) {
		printf("CANIF environment variable must contain the test interface\n");
		return KSFT_FAIL;
	}

	strncpy(CANIF, ifname, sizeof(CANIF) - 1);

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CAN));
	if (s < 0) {
		perror("socket");
		return 1;
	}

	if (strcmp(CANIF, "any") == 0)
		sll.sll_ifindex = 0;
	else
		sll.sll_ifindex = if_nametoindex(CANIF);

	if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("bind");
		return 1;
	}

	can_pf_packet_send(s, CAN_MAX_DLEN);
	can_pf_packet_send(s, 255);
	can_pf_packet_read(s);

	close(s);

	return 0;
}
