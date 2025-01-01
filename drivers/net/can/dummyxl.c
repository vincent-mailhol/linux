// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2025 Vincent Mailhol <mailhol@kernel.org> */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/units.h>

#include <linux/can.h>
#include <linux/can/bittiming.h>
#include <linux/can/dev.h>
#include <linux/can/skb.h>

struct dummyxl {
	struct can_priv can;
	struct net_device *dev;
};

static struct dummyxl *dummyxl;

static const struct can_bittiming_const dummyxl_bittiming_const = {
	.name = "dummyxl nominal",
	.tseg1_min = 2,
	.tseg1_max = 256,
	.tseg2_min = 2,
	.tseg2_max = 128,
	.sjw_max = 128,
	.brp_min = 1,
	.brp_max = 512,
	.brp_inc = 1
};

static const struct can_bittiming_const dummyxl_fd_databittiming_const = {
	.name = "dummyxl FD",
	.tseg1_min = 2,
	.tseg1_max = 256,
	.tseg2_min = 2,
	.tseg2_max = 128,
	.sjw_max = 128,
	.brp_min = 1,
	.brp_max = 512,
	.brp_inc = 1
};

static const struct can_tdc_const dummyxl_fd_tdc_const = {
	.tdcv_min = 0,
	.tdcv_max = 0, /* Manual mode not supported. */
	.tdco_min = 0,
	.tdco_max = 127,
	.tdcf_min = 0,
	.tdcf_max = 127
};

static const struct can_bittiming_const dummyxl_xl_databittiming_const = {
	.name = "dummyxl XL",
	.tseg1_min = 2,
	.tseg1_max = 256,
	.tseg2_min = 2,
	.tseg2_max = 128,
	.sjw_max = 128,
	.brp_min = 1,
	.brp_max = 512,
	.brp_inc = 1
};

static const struct can_tdc_const dummyxl_xl_tdc_const = {
	.tdcv_min = 0,
	.tdcv_max = 0, /* Manual mode not supported. */
	.tdco_min = 0,
	.tdco_max = 127,
	.tdcf_min = 0,
	.tdcf_max = 127
};

static void dummyxl_print_bittiming(struct net_device *dev, struct can_bittiming *bt)
{
	netdev_info(dev, "\tbitrate: %u\n", bt->bitrate);
	netdev_info(dev, "\tsample_point: %u\n", bt->sample_point);
	netdev_info(dev, "\ttq: %u\n", bt->tq);
	netdev_info(dev, "\tprop_seg: %u\n", bt->prop_seg);
	netdev_info(dev, "\tphase_seg1: %u\n", bt->phase_seg1);
	netdev_info(dev, "\tphase_seg2: %u\n", bt->phase_seg2);
	netdev_info(dev, "\tsjw: %u\n", bt->sjw);
	netdev_info(dev, "\tbrp: %u\n", bt->brp);
}

static void dummyxl_print_tdc(struct net_device *dev, struct can_tdc *tdc)
{
	netdev_info(dev, "\t\ttdcv: %u\n", tdc->tdcv);
	netdev_info(dev, "\t\ttdco: %u\n", tdc->tdco);
	netdev_info(dev, "\t\ttdcf: %u\n", tdc->tdcf);
}

static void dummyxl_print_pwm(struct net_device *dev, struct can_pwm *pwm,
			      struct can_bittiming *dbt)
{
	u32 pwmo = can_get_pwmo(pwm, dbt);

	netdev_info(dev, "\t\tpwms: %u\n", pwm->pwms);
	netdev_info(dev, "\t\tpwml: %u\n", pwm->pwml);
	netdev_info(dev, "\t\tpwmo: %u\n", pwmo);
}

static int dummyxl_netdev_open(struct net_device *dev)
{
	struct dummyxl *priv = netdev_priv(dev);
	struct can_priv *can_priv = &priv->can;
	int ret;

	netdev_info(dev, "CAN CC nominal bittiming:\n");
	dummyxl_print_bittiming(dev, &can_priv->bittiming);
	netdev_info(dev, "\n");

	if (can_priv->ctrlmode & CAN_CTRLMODE_FD) {
		netdev_info(dev, "CAN FD databittiming:\n");
		dummyxl_print_bittiming(dev, &can_priv->fd.data_bittiming);
		if (can_fd_tdc_is_enabled(can_priv)) {
			netdev_info(dev, "\tCAN FD TDC:\n");
			dummyxl_print_tdc(dev, &can_priv->fd.tdc);
		} else {
			netdev_info(dev, "\tCAN FD TDC is off\n");
		}
	} else {
		netdev_info(dev, "CAN FD is off\n");
	}
	netdev_info(dev, "\n");

	if (can_priv->ctrlmode & CAN_CTRLMODE_XL) {
		netdev_info(dev, "CAN XL databittiming:\n");
		dummyxl_print_bittiming(dev, &can_priv->xl.data_bittiming);
		if (can_xl_tdc_is_enabled(can_priv)) {
			netdev_info(dev, "\tCAN XL TDC:\n");
			dummyxl_print_tdc(dev, &can_priv->xl.tdc);
		} else {
			netdev_info(dev, "\tCAN XL TDC is off\n");
		}
		if (can_priv->ctrlmode & CAN_CTRLMODE_XL_PWM) {
			netdev_info(dev, "\tCAN XL PWM:\n");
			dummyxl_print_pwm(dev, &can_priv->xl_pwm,
					  &can_priv->xl.data_bittiming);
		} else {
			netdev_info(dev, "\tCAN XL PWM is off\n");
		}
	} else {
		netdev_info(dev, "CAN XL is off\n");
	}
	netdev_info(dev, "\n");

	ret = open_candev(dev);
	if (ret)
		return ret;
	netif_start_queue(dev);
	netdev_info(dev, "dummyxl is up\n");

	return 0;
}

static int dummyxl_netdev_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	close_candev(dev);
	netdev_info(dev, "dummyxl is down\n");

	return 0;
}

static netdev_tx_t dummyxl_start_xmit(struct sk_buff *skb,
				      struct net_device *dev)
{
	if (can_is_canxl_skb(skb))
		netdev_info(dev, "Received CAN XL skb\n");
	else if (can_is_canfd_skb(skb))
		netdev_info(dev, "Received CAN FD skb\n");
	else if (can_is_can_skb(skb))
		netdev_info(dev, "Received Classical CAN skb\n");
	else
		netdev_info(dev, "Received an odd skb?!\n");
	kfree_skb(skb);
	dev->stats.tx_dropped++;

	return NETDEV_TX_OK;
}

static const struct net_device_ops dummyxl_netdev_ops = {
	.ndo_open = dummyxl_netdev_open,
	.ndo_stop = dummyxl_netdev_close,
	.ndo_start_xmit = dummyxl_start_xmit,
};

static int __init dummyxl_init(void)
{
	struct net_device *dev;
	struct dummyxl *priv;
	int ret;

	dev = alloc_candev(sizeof(struct dummyxl), 0);
	if (!dev)
		return -ENOMEM;

	dev->netdev_ops = &dummyxl_netdev_ops;
	priv = netdev_priv(dev);
	priv->can.bittiming_const = &dummyxl_bittiming_const;
	priv->can.bitrate_max = 8 * MEGA /* BPS */;
	priv->can.clock.freq = 80 * MEGA /* Hz */;
	priv->can.fd.data_bittiming_const = &dummyxl_fd_databittiming_const;
	priv->can.fd.tdc_const = &dummyxl_fd_tdc_const;
	priv->can.xl.data_bittiming_const = &dummyxl_xl_databittiming_const;
	priv->can.xl.tdc_const = &dummyxl_xl_tdc_const;
	priv->can.ctrlmode_supported = CAN_CTRLMODE_LISTENONLY |
		CAN_CTRLMODE_FD | CAN_CTRLMODE_TDC_AUTO |
		CAN_CTRLMODE_XL | CAN_CTRLMODE_XL_TDC_AUTO;
	priv->dev = dev;

	ret = register_candev(priv->dev);
	if (ret) {
		free_candev(priv->dev);
		return ret;
	}

	dummyxl = priv;
	netdev_info(dev, "dummyxl OK\n");

	return 0;
}

static void __exit dummyxl_exit(void)
{
	struct net_device *dev = dummyxl->dev;

	netdev_info(dev, "dummyxl bye bye\n");
	unregister_candev(dev);
	free_candev(dev);
}

module_init(dummyxl_init);
module_exit(dummyxl_exit);

MODULE_DESCRIPTION("A dummy module just to check the CAN XL netlink interface");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Mailhol <mailhol.vincent@wanadoo.fr>");
