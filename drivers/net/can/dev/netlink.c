// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2005 Marc Kleine-Budde, Pengutronix
 * Copyright (C) 2006 Andrey Volkov, Varma Electronics
 * Copyright (C) 2008-2009 Wolfgang Grandegger <wg@grandegger.com>
 * Copyright (C) 2021 Vincent Mailhol <mailhol.vincent@wanadoo.fr>
 */

#include <linux/can/dev.h>
#include <net/rtnetlink.h>

static const struct nla_policy can_policy[IFLA_CAN_MAX + 1] = {
	[IFLA_CAN_STATE] = { .type = NLA_U32 },
	[IFLA_CAN_CTRLMODE] = { .len = sizeof(struct can_ctrlmode) },
	[IFLA_CAN_RESTART_MS] = { .type = NLA_U32 },
	[IFLA_CAN_RESTART] = { .type = NLA_U32 },
	[IFLA_CAN_BITTIMING] = { .len = sizeof(struct can_bittiming) },
	[IFLA_CAN_BITTIMING_CONST] = { .len = sizeof(struct can_bittiming_const) },
	[IFLA_CAN_CLOCK] = { .len = sizeof(struct can_clock) },
	[IFLA_CAN_BERR_COUNTER] = { .len = sizeof(struct can_berr_counter) },
	[IFLA_CAN_DATA_BITTIMING] = { .len = sizeof(struct can_bittiming) },
	[IFLA_CAN_DATA_BITTIMING_CONST] = { .len = sizeof(struct can_bittiming_const) },
	[IFLA_CAN_TERMINATION] = { .type = NLA_U16 },
	[IFLA_CAN_TDC] = { .type = NLA_NESTED },
	[IFLA_CAN_CTRLMODE_EXT] = { .type = NLA_NESTED },
	[IFLA_CAN_XL_DATA_BITTIMING] = { .len = sizeof(struct can_bittiming) },
	[IFLA_CAN_XL_DATA_BITTIMING_CONST] = { .len = sizeof(struct can_bittiming_const) },
	[IFLA_CAN_XL_TDC] = { .type = NLA_NESTED },
};

static const struct nla_policy can_tdc_policy[IFLA_CAN_TDC_MAX + 1] = {
	[IFLA_CAN_TDC_TDCV_MIN] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCV_MAX] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCO_MIN] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCO_MAX] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCF_MIN] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCF_MAX] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCV] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCO] = { .type = NLA_U32 },
	[IFLA_CAN_TDC_TDCF] = { .type = NLA_U32 },
};

static int can_validate_bittiming(const struct can_bittiming *bt,
				  struct netlink_ext_ack *extack)
{
	/* sample point is in one-tenth of a percent */
	if (bt->sample_point >= 1000) {
		NL_SET_ERR_MSG(extack, "sample point must be between 0 and 100%");

		return -EINVAL;
	}

	return 0;
}

static int can_validate_tdc(struct nlattr *data_tdc,
			    bool tdc_auto, bool tdc_manual,
			    struct netlink_ext_ack *extack)
{
	int err;

	if (tdc_auto && tdc_manual) {
		NL_SET_ERR_MSG_FMT(extack,
				   "TDC manual and auto modes are mutually exclusive");
		return -EOPNOTSUPP;
	}

	/* If one of the CAN_CTRLMODE_TDC_* flag is set then
	 * TDC must be set and vice-versa
	 */
	if ((tdc_auto || tdc_manual) && !data_tdc) {
		NL_SET_ERR_MSG_FMT(extack, "TDC parameters are missing");
		return -EOPNOTSUPP;
	}
	if (!(tdc_auto || tdc_manual) && data_tdc) {
		NL_SET_ERR_MSG_FMT(extack,
				   "TDC mode (auto or manual) is missing");
		return -EOPNOTSUPP;
	}

	/* If providing TDC parameters, at least TDCO is needed. TDCV
	 * is needed if and only if CAN_CTRLMODE_TDC_MANUAL is set
	 */
	if (data_tdc) {
		struct nlattr *tb_tdc[IFLA_CAN_TDC_MAX + 1];

		err = nla_parse_nested(tb_tdc, IFLA_CAN_TDC_MAX,
				       data_tdc, can_tdc_policy, extack);
		if (err)
			return err;

		if (tb_tdc[IFLA_CAN_TDC_TDCV]) {
			if (tdc_auto) {
				NL_SET_ERR_MSG_FMT(extack,
						   "TDCV argument is incompatible with TDC auto mode");
				return -EOPNOTSUPP;
			}
		} else {
			if (tdc_manual) {
				NL_SET_ERR_MSG_FMT(extack,
						   "TDC manual mode requires the TDCV argument");
				return -EOPNOTSUPP;
			}
		}

		if (!tb_tdc[IFLA_CAN_TDC_TDCO]) {
			NL_SET_ERR_MSG_FMT(extack,
					   "TDCO option is missing");
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int can_validate(struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	bool is_can_fd = false, is_can_xl = false;
	int err;

	/* Make sure that valid CAN FD configurations always consist of
	 * - nominal/arbitration bittiming
	 * - data bittiming
	 * - control mode with CAN_CTRLMODE_FD set
	 * - TDC parameters are coherent (details below)
	 */

	if (!data)
		return 0;

	if (data[IFLA_CAN_CTRLMODE]) {
		struct can_ctrlmode *cm = nla_data(data[IFLA_CAN_CTRLMODE]);

		is_can_fd = cm->flags & cm->mask & CAN_CTRLMODE_FD;
		is_can_xl = cm->flags & cm->mask & CAN_CTRLMODE_XL;

		err = can_validate_tdc(data[IFLA_CAN_TDC],
				       cm->flags & CAN_CTRLMODE_TDC_AUTO,
				       cm->flags & CAN_CTRLMODE_TDC_MANUAL,
				       extack);
		if (err)
			return err;
	}

	if (data[IFLA_CAN_BITTIMING]) {
		struct can_bittiming bt;

		memcpy(&bt, nla_data(data[IFLA_CAN_BITTIMING]), sizeof(bt));
		err = can_validate_bittiming(&bt, extack);
		if (err)
			return err;
	}

	if (is_can_fd) {
		if (!data[IFLA_CAN_BITTIMING] || !data[IFLA_CAN_DATA_BITTIMING]) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Provide both nominal and FD data bittiming");
			return -EOPNOTSUPP;
		}
	}
	if (is_can_xl) {
		if (!data[IFLA_CAN_BITTIMING] || !data[IFLA_CAN_XL_DATA_BITTIMING]) {
			NL_SET_ERR_MSG_FMT(extack,
					   "Provide both nominal and XL data bittiming");
			return -EOPNOTSUPP;
		}
	}

	if (data[IFLA_CAN_DATA_BITTIMING] || data[IFLA_CAN_TDC]) {
		if (!is_can_fd) {
			NL_SET_ERR_MSG_FMT(extack,
					   "CAN FD is required to use FD data bittiming or FD TDC");
			return -EOPNOTSUPP;
		}
	}
	if (data[IFLA_CAN_XL_DATA_BITTIMING] || data[IFLA_CAN_XL_TDC]) {
		if (!is_can_xl) {
			NL_SET_ERR_MSG_FMT(extack,
					   "CAN XL is required to use XL data bittiming or XL TDC");
			return -EOPNOTSUPP;
		}
	}

	if (data[IFLA_CAN_DATA_BITTIMING]) {
		struct can_bittiming bt;

		memcpy(&bt, nla_data(data[IFLA_CAN_DATA_BITTIMING]), sizeof(bt));
		err = can_validate_bittiming(&bt, extack);
		if (err)
			return err;
	}
	if (data[IFLA_CAN_XL_DATA_BITTIMING]) {
		struct can_bittiming bt;

		memcpy(&bt, nla_data(data[IFLA_CAN_XL_DATA_BITTIMING]), sizeof(bt));
		err = can_validate_bittiming(&bt, extack);
		if (err)
			return err;
	}

	return 0;
}

static int can_tdc_changelink(struct data_bittiming_params *dbt_params,
			      bool tdc_is_enabled, const struct nlattr *nla,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb_tdc[IFLA_CAN_TDC_MAX + 1];
	struct can_tdc tdc = { 0 };
	const struct can_tdc_const *tdc_const = dbt_params->tdc_const;
	int err;

	if (!tdc_const || !tdc_is_enabled)
		return -EOPNOTSUPP;

	err = nla_parse_nested(tb_tdc, IFLA_CAN_TDC_MAX, nla,
			       can_tdc_policy, extack);
	if (err)
		return err;

	if (tb_tdc[IFLA_CAN_TDC_TDCV]) {
		u32 tdcv = nla_get_u32(tb_tdc[IFLA_CAN_TDC_TDCV]);

		if (tdcv < tdc_const->tdcv_min || tdcv > tdc_const->tdcv_max)
			return -EINVAL;

		tdc.tdcv = tdcv;
	}

	if (tb_tdc[IFLA_CAN_TDC_TDCO]) {
		u32 tdco = nla_get_u32(tb_tdc[IFLA_CAN_TDC_TDCO]);

		if (tdco < tdc_const->tdco_min || tdco > tdc_const->tdco_max)
			return -EINVAL;

		tdc.tdco = tdco;
	}

	if (tb_tdc[IFLA_CAN_TDC_TDCF]) {
		u32 tdcf = nla_get_u32(tb_tdc[IFLA_CAN_TDC_TDCF]);

		if (tdcf < tdc_const->tdcf_min || tdcf > tdc_const->tdcf_max)
			return -EINVAL;

		tdc.tdcf = tdcf;
	}

	dbt_params->tdc = tdc;

	return 0;
}

static int can_dbt_changelink(struct net_device *dev,
			      struct nlattr *data_databittiming,
			      struct data_bittiming_params *dbt_params,
			      struct nlattr *data_tdc, bool tdc_flags_provided,
			      bool tdc_is_enabled, u32 tdc_mask,
			      struct netlink_ext_ack *extack)
{
	struct can_priv *priv = netdev_priv(dev);
	struct can_bittiming dbt;
	int err;

	if (!data_databittiming)
		return 0;

	/* Do not allow changing bittiming while running */
	if (dev->flags & IFF_UP)
		return -EBUSY;

	/* Calculate bittiming parameters based on data_bittiming_const
	 * if set, otherwise pass bitrate directly via do_set_bitrate().
	 * Bail out if neither is given.
	 */
	if (!dbt_params->data_bittiming_const && !dbt_params->do_set_data_bittiming &&
	    !dbt_params->data_bitrate_const)
		return -EOPNOTSUPP;

	memcpy(&dbt, nla_data(data_databittiming), sizeof(dbt));
	err = can_get_bittiming(dev, &dbt, dbt_params->data_bittiming_const,
				dbt_params->data_bitrate_const,
				dbt_params->data_bitrate_const_cnt, extack);
	if (err)
		return err;

	if (priv->bitrate_max && dbt.bitrate > priv->bitrate_max) {
		NL_SET_ERR_MSG_FMT(extack,
				   "CAN data bitrate %u bps surpasses transceiver capabilities of %u bps",
				   dbt.bitrate, priv->bitrate_max);
		return -EINVAL;
	}

	memset(&dbt_params->tdc, 0, sizeof(dbt_params->tdc));
	if (data_tdc) {
		/* TDC parameters are provided: use them */
		err = can_tdc_changelink(dbt_params, tdc_is_enabled, data_tdc,
					 extack);
		if (err) {
			priv->ctrlmode &= ~tdc_mask;
			return err;
		}
	} else if (!tdc_flags_provided) {
		/* Neither of TDC parameters nor TDC flags are provided:
		 * do calculation
		 */
		can_calc_tdco(&dbt_params->tdc, dbt_params->tdc_const, &dbt,
			      &priv->ctrlmode, priv->ctrlmode_supported);
	} /* else: both CAN_CTRLMODE_TDC_{AUTO,MANUAL} are explicitly
	   * turned off. TDC is disabled: do nothing
	   */

	memcpy(&dbt_params->data_bittiming, &dbt, sizeof(dbt));

	if (dbt_params->do_set_data_bittiming) {
		/* Finally, set the bit-timing registers */
		err = dbt_params->do_set_data_bittiming(dev);
		if (err)
			return err;
	}

	return 0;
}

static int can_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	bool fd_tdc_flag_provided = false, xl_tdc_flag_provided = false;
	struct can_priv *priv = netdev_priv(dev);
	int err;

	/* We need synchronization with dev->stop() */
	ASSERT_RTNL();

	if (data[IFLA_CAN_CTRLMODE]) {
		struct can_ctrlmode *cm;
		u32 ctrlstatic;
		u32 maskedflags;

		/* Do not allow changing controller mode while running */
		if (dev->flags & IFF_UP)
			return -EBUSY;
		cm = nla_data(data[IFLA_CAN_CTRLMODE]);
		ctrlstatic = can_get_static_ctrlmode(priv);
		maskedflags = cm->flags & cm->mask;

		/* check whether provided bits are allowed to be passed */
		if (maskedflags & ~(priv->ctrlmode_supported | ctrlstatic))
			return -EOPNOTSUPP;

		/* do not check for static fd-non-iso if 'fd' is disabled */
		if (!(maskedflags & CAN_CTRLMODE_FD))
			ctrlstatic &= ~CAN_CTRLMODE_FD_NON_ISO;

		/* make sure static options are provided by configuration */
		if ((maskedflags & ctrlstatic) != ctrlstatic)
			return -EOPNOTSUPP;

		/* clear bits to be modified and copy the flag values */
		priv->ctrlmode &= ~cm->mask;
		priv->ctrlmode |= maskedflags;

		/* CAN_CTRLMODE_{FD,XL} can only be set when driver supports FD/XL */
		if (priv->ctrlmode & CAN_CTRLMODE_XL) {
			dev->mtu = CANXL_MAX_MTU;
		} else if (priv->ctrlmode & CAN_CTRLMODE_FD) {
			dev->mtu = CANFD_MTU;
		} else {
			dev->mtu = CAN_MTU;
			memset(&priv->fd.data_bittiming, 0,
			       sizeof(priv->fd.data_bittiming));
			priv->ctrlmode &= ~CAN_CTRLMODE_FD_TDC_MASK;
			memset(&priv->fd.tdc, 0, sizeof(priv->fd.tdc));
		}

		fd_tdc_flag_provided = cm->mask & CAN_CTRLMODE_FD_TDC_MASK;
		xl_tdc_flag_provided = cm->mask & CAN_CTRLMODE_XL_TDC_MASK;
		/* CAN_CTRLMODE_(XL_)TDC_{AUTO,MANUAL} are mutually
		 * exclusive: make sure to turn the other one off
		 */
		if (fd_tdc_flag_provided)
			priv->ctrlmode &= cm->flags | ~CAN_CTRLMODE_FD_TDC_MASK;
		if (xl_tdc_flag_provided)
			priv->ctrlmode &= cm->flags | ~CAN_CTRLMODE_XL_TDC_MASK;
	}

	if (data[IFLA_CAN_BITTIMING]) {
		struct can_bittiming bt;

		/* Do not allow changing bittiming while running */
		if (dev->flags & IFF_UP)
			return -EBUSY;

		/* Calculate bittiming parameters based on
		 * bittiming_const if set, otherwise pass bitrate
		 * directly via do_set_bitrate(). Bail out if neither
		 * is given.
		 */
		if (!priv->bittiming_const && !priv->do_set_bittiming &&
		    !priv->bitrate_const)
			return -EOPNOTSUPP;

		memcpy(&bt, nla_data(data[IFLA_CAN_BITTIMING]), sizeof(bt));
		err = can_get_bittiming(dev, &bt,
					priv->bittiming_const,
					priv->bitrate_const,
					priv->bitrate_const_cnt,
					extack);
		if (err)
			return err;

		if (priv->bitrate_max && bt.bitrate > priv->bitrate_max) {
			NL_SET_ERR_MSG_FMT(extack,
					   "arbitration bitrate %u bps surpasses transceiver capabilities of %u bps",
					   bt.bitrate, priv->bitrate_max);
			return -EINVAL;
		}

		memcpy(&priv->bittiming, &bt, sizeof(bt));

		if (priv->do_set_bittiming) {
			/* Finally, set the bit-timing registers */
			err = priv->do_set_bittiming(dev);
			if (err)
				return err;
		}
	}

	if (data[IFLA_CAN_RESTART_MS]) {
		/* Do not allow changing restart delay while running */
		if (dev->flags & IFF_UP)
			return -EBUSY;
		priv->restart_ms = nla_get_u32(data[IFLA_CAN_RESTART_MS]);
	}

	if (data[IFLA_CAN_RESTART]) {
		/* Do not allow a restart while not running */
		if (!(dev->flags & IFF_UP))
			return -EINVAL;
		err = can_restart_now(dev);
		if (err)
			return err;
	}

	/* CAN FD */
	err = can_dbt_changelink(dev, data[IFLA_CAN_DATA_BITTIMING], &priv->fd,
				 data[IFLA_CAN_TDC], fd_tdc_flag_provided,
				 can_fd_tdc_is_enabled(priv),
				 CAN_CTRLMODE_FD_TDC_MASK, extack);
	if (err)
		return err;

	/* CAN XL */
	err = can_dbt_changelink(dev,
				 data[IFLA_CAN_XL_DATA_BITTIMING], &priv->xl,
				 data[IFLA_CAN_XL_TDC], xl_tdc_flag_provided,
				 can_xl_tdc_is_enabled(priv),
				 CAN_CTRLMODE_XL_TDC_MASK, extack);
	if (err)
		return err;

	if (data[IFLA_CAN_TERMINATION]) {
		const u16 termval = nla_get_u16(data[IFLA_CAN_TERMINATION]);
		const unsigned int num_term = priv->termination_const_cnt;
		unsigned int i;

		if (!priv->do_set_termination)
			return -EOPNOTSUPP;

		/* check whether given value is supported by the interface */
		for (i = 0; i < num_term; i++) {
			if (termval == priv->termination_const[i])
				break;
		}
		if (i >= num_term)
			return -EINVAL;

		/* Finally, set the termination value */
		err = priv->do_set_termination(dev, termval);
		if (err)
			return err;

		priv->termination = termval;
	}

	return 0;
}

static size_t can_tdc_get_size(struct data_bittiming_params *dbt_params,
			       bool tdc_is_enabled, bool tdc_manual)
{
	size_t size;

	if (!dbt_params->tdc_const)
		return 0;

	size = nla_total_size(0);			/* nest IFLA_CAN_TDC */
	if (tdc_manual) {
		size += nla_total_size(sizeof(u32));	/* IFLA_CAN_TDCV_MIN */
		size += nla_total_size(sizeof(u32));	/* IFLA_CAN_TDCV_MAX */
	}
	size += nla_total_size(sizeof(u32));		/* IFLA_CAN_TDCO_MIN */
	size += nla_total_size(sizeof(u32));		/* IFLA_CAN_TDCO_MAX */
	if (dbt_params->tdc_const->tdcf_max) {
		size += nla_total_size(sizeof(u32));	/* IFLA_CAN_TDCF_MIN */
		size += nla_total_size(sizeof(u32));	/* IFLA_CAN_TDCF_MAX */
	}

	if (tdc_is_enabled) {
		if (tdc_manual || dbt_params->do_get_auto_tdcv)
			size += nla_total_size(sizeof(u32));	/* IFLA_CAN_TDCV */
		size += nla_total_size(sizeof(u32));		/* IFLA_CAN_TDCO */
		if (dbt_params->tdc_const->tdcf_max)
			size += nla_total_size(sizeof(u32));	/* IFLA_CAN_TDCF */
	}

	return size;
}

static size_t can_ctrlmode_ext_get_size(void)
{
	return nla_total_size(0) +		/* nest IFLA_CAN_CTRLMODE_EXT */
		nla_total_size(sizeof(u32));	/* IFLA_CAN_CTRLMODE_SUPPORTED */
}

static size_t can_get_size(const struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	size_t size = 0;

	if (priv->bittiming.bitrate)				/* IFLA_CAN_BITTIMING */
		size += nla_total_size(sizeof(struct can_bittiming));
	if (priv->bittiming_const)				/* IFLA_CAN_BITTIMING_CONST */
		size += nla_total_size(sizeof(struct can_bittiming_const));
	size += nla_total_size(sizeof(struct can_clock));	/* IFLA_CAN_CLOCK */
	size += nla_total_size(sizeof(u32));			/* IFLA_CAN_STATE */
	size += nla_total_size(sizeof(struct can_ctrlmode));	/* IFLA_CAN_CTRLMODE */
	size += nla_total_size(sizeof(u32));			/* IFLA_CAN_RESTART_MS */
	if (priv->do_get_berr_counter)				/* IFLA_CAN_BERR_COUNTER */
		size += nla_total_size(sizeof(struct can_berr_counter));
	if (priv->fd.data_bittiming.bitrate)			/* IFLA_CAN_DATA_BITTIMING */
		size += nla_total_size(sizeof(struct can_bittiming));
	if (priv->fd.data_bittiming_const)			/* IFLA_CAN_DATA_BITTIMING_CONST */
		size += nla_total_size(sizeof(struct can_bittiming_const));
	if (priv->termination_const) {
		size += nla_total_size(sizeof(priv->termination));		/* IFLA_CAN_TERMINATION */
		size += nla_total_size(sizeof(*priv->termination_const) *	/* IFLA_CAN_TERMINATION_CONST */
				       priv->termination_const_cnt);
	}
	if (priv->bitrate_const)				/* IFLA_CAN_BITRATE_CONST */
		size += nla_total_size(sizeof(*priv->bitrate_const) *
				       priv->bitrate_const_cnt);
	if (priv->fd.data_bitrate_const)			/* IFLA_CAN_DATA_BITRATE_CONST */
		size += nla_total_size(sizeof(*priv->fd.data_bitrate_const) *
				       priv->fd.data_bitrate_const_cnt);
	size += sizeof(priv->bitrate_max);			/* IFLA_CAN_BITRATE_MAX */
	size += can_tdc_get_size(&priv->fd,			/* IFLA_CAN_TDC */
				 can_fd_tdc_is_enabled(priv),
				 priv->ctrlmode & CAN_CTRLMODE_TDC_MANUAL);
	size += can_ctrlmode_ext_get_size();			/* IFLA_CAN_CTRLMODE_EXT */
	if (priv->xl.data_bittiming.bitrate)			/* IFLA_CAN_XL_DATA_BITTIMING */
		size += nla_total_size(sizeof(struct can_bittiming));
	if (priv->xl.data_bittiming_const)			/* IFLA_CAN_XL_DATA_BITTIMING_CONST */
		size += nla_total_size(sizeof(struct can_bittiming_const));
	if (priv->xl.data_bitrate_const)			/* IFLA_CAN_DATA_BITRATE_CONST */
		size += nla_total_size(sizeof(*priv->xl.data_bitrate_const) *
				       priv->xl.data_bitrate_const_cnt);
	size += can_tdc_get_size(&priv->xl,			/* IFLA_CAN_XL_TDC */
				 can_xl_tdc_is_enabled(priv),
				 priv->ctrlmode & CAN_CTRLMODE_XL_TDC_MANUAL);

	return size;
}

static int can_tdc_fill_info(struct sk_buff *skb,  const struct net_device *dev,
			     struct data_bittiming_params *dbt_params,
			     bool tdc_is_enabled, bool tdc_manual)
{
	struct nlattr *nest;
	struct can_tdc *tdc = &dbt_params->tdc;
	const struct can_tdc_const *tdc_const = dbt_params->tdc_const;

	if (!tdc_const)
		return 0;

	nest = nla_nest_start(skb, IFLA_CAN_TDC);
	if (!nest)
		return -EMSGSIZE;

	if (tdc_manual &&
	    (nla_put_u32(skb, IFLA_CAN_TDC_TDCV_MIN, tdc_const->tdcv_min) ||
	     nla_put_u32(skb, IFLA_CAN_TDC_TDCV_MAX, tdc_const->tdcv_max)))
		goto err_cancel;
	if (nla_put_u32(skb, IFLA_CAN_TDC_TDCO_MIN, tdc_const->tdco_min) ||
	    nla_put_u32(skb, IFLA_CAN_TDC_TDCO_MAX, tdc_const->tdco_max))
		goto err_cancel;
	if (tdc_const->tdcf_max &&
	    (nla_put_u32(skb, IFLA_CAN_TDC_TDCF_MIN, tdc_const->tdcf_min) ||
	     nla_put_u32(skb, IFLA_CAN_TDC_TDCF_MAX, tdc_const->tdcf_max)))
		goto err_cancel;

	if (tdc_is_enabled) {
		u32 tdcv;
		int err = -EINVAL;

		if (tdc_manual) {
			tdcv = tdc->tdcv;
			err = 0;
		} else if (dbt_params->do_get_auto_tdcv) {
			err = dbt_params->do_get_auto_tdcv(dev, &tdcv);
		}
		if (!err && nla_put_u32(skb, IFLA_CAN_TDC_TDCV, tdcv))
			goto err_cancel;
		if (nla_put_u32(skb, IFLA_CAN_TDC_TDCO, tdc->tdco))
			goto err_cancel;
		if (tdc_const->tdcf_max &&
		    nla_put_u32(skb, IFLA_CAN_TDC_TDCF, tdc->tdcf))
			goto err_cancel;
	}

	nla_nest_end(skb, nest);
	return 0;

err_cancel:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int can_ctrlmode_ext_fill_info(struct sk_buff *skb,
				      const struct can_priv *priv)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, IFLA_CAN_CTRLMODE_EXT);
	if (!nest)
		return -EMSGSIZE;

	if (nla_put_u32(skb, IFLA_CAN_CTRLMODE_SUPPORTED,
			priv->ctrlmode_supported)) {
		nla_nest_cancel(skb, nest);
		return -EMSGSIZE;
	}

	nla_nest_end(skb, nest);
	return 0;
}

static int can_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	struct can_ctrlmode cm = {.flags = priv->ctrlmode};
	struct can_berr_counter bec = { };
	enum can_state state = priv->state;

	if (priv->do_get_state)
		priv->do_get_state(dev, &state);

	if ((priv->bittiming.bitrate != CAN_BITRATE_UNSET &&
	     priv->bittiming.bitrate != CAN_BITRATE_UNKNOWN &&
	     nla_put(skb, IFLA_CAN_BITTIMING,
		     sizeof(priv->bittiming), &priv->bittiming)) ||

	    (priv->bittiming_const &&
	     nla_put(skb, IFLA_CAN_BITTIMING_CONST,
		     sizeof(*priv->bittiming_const), priv->bittiming_const)) ||

	    nla_put(skb, IFLA_CAN_CLOCK, sizeof(priv->clock), &priv->clock) ||
	    nla_put_u32(skb, IFLA_CAN_STATE, state) ||
	    nla_put(skb, IFLA_CAN_CTRLMODE, sizeof(cm), &cm) ||
	    nla_put_u32(skb, IFLA_CAN_RESTART_MS, priv->restart_ms) ||

	    (priv->do_get_berr_counter &&
	     !priv->do_get_berr_counter(dev, &bec) &&
	     nla_put(skb, IFLA_CAN_BERR_COUNTER, sizeof(bec), &bec)) ||

	    (priv->fd.data_bittiming.bitrate &&
	     nla_put(skb, IFLA_CAN_DATA_BITTIMING,
		     sizeof(priv->fd.data_bittiming), &priv->fd.data_bittiming)) ||

	    (priv->fd.data_bittiming_const &&
	     nla_put(skb, IFLA_CAN_DATA_BITTIMING_CONST,
		     sizeof(*priv->fd.data_bittiming_const),
		     priv->fd.data_bittiming_const)) ||

	    (priv->termination_const &&
	     (nla_put_u16(skb, IFLA_CAN_TERMINATION, priv->termination) ||
	      nla_put(skb, IFLA_CAN_TERMINATION_CONST,
		      sizeof(*priv->termination_const) *
		      priv->termination_const_cnt,
		      priv->termination_const))) ||

	    (priv->bitrate_const &&
	     nla_put(skb, IFLA_CAN_BITRATE_CONST,
		     sizeof(*priv->bitrate_const) *
		     priv->bitrate_const_cnt,
		     priv->bitrate_const)) ||

	    (priv->fd.data_bitrate_const &&
	     nla_put(skb, IFLA_CAN_DATA_BITRATE_CONST,
		     sizeof(*priv->fd.data_bitrate_const) *
		     priv->fd.data_bitrate_const_cnt,
		     priv->fd.data_bitrate_const)) ||

	    (nla_put(skb, IFLA_CAN_BITRATE_MAX,
		     sizeof(priv->bitrate_max),
		     &priv->bitrate_max)) ||

	    can_tdc_fill_info(skb, dev, &priv->fd, can_fd_tdc_is_enabled(priv),
			      priv->ctrlmode & CAN_CTRLMODE_TDC_MANUAL) ||

	    can_ctrlmode_ext_fill_info(skb, priv) ||

	    (priv->xl.data_bittiming.bitrate &&
	     nla_put(skb, IFLA_CAN_XL_DATA_BITTIMING,
		     sizeof(priv->xl.data_bittiming), &priv->xl.data_bittiming)) ||

	    (priv->xl.data_bittiming_const &&
	     nla_put(skb, IFLA_CAN_XL_DATA_BITTIMING_CONST,
		     sizeof(*priv->xl.data_bittiming_const),
		     priv->xl.data_bittiming_const)) ||

	    (priv->xl.data_bitrate_const &&
	     nla_put(skb, IFLA_CAN_XL_DATA_BITRATE_CONST,
		     sizeof(*priv->xl.data_bitrate_const) *
		     priv->xl.data_bitrate_const_cnt,
		     priv->xl.data_bitrate_const)) ||

	    can_tdc_fill_info(skb, dev, &priv->xl, can_xl_tdc_is_enabled(priv),
			      priv->ctrlmode & CAN_CTRLMODE_XL_TDC_MANUAL)
	    )

		return -EMSGSIZE;

	return 0;
}

static size_t can_get_xstats_size(const struct net_device *dev)
{
	return sizeof(struct can_device_stats);
}

static int can_fill_xstats(struct sk_buff *skb, const struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	if (nla_put(skb, IFLA_INFO_XSTATS,
		    sizeof(priv->can_stats), &priv->can_stats))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static int can_newlink(struct net *src_net, struct net_device *dev,
		       struct nlattr *tb[], struct nlattr *data[],
		       struct netlink_ext_ack *extack)
{
	return -EOPNOTSUPP;
}

static void can_dellink(struct net_device *dev, struct list_head *head)
{
}

struct rtnl_link_ops can_link_ops __read_mostly = {
	.kind		= "can",
	.netns_refund	= true,
	.maxtype	= IFLA_CAN_MAX,
	.policy		= can_policy,
	.setup		= can_setup,
	.validate	= can_validate,
	.newlink	= can_newlink,
	.changelink	= can_changelink,
	.dellink	= can_dellink,
	.get_size	= can_get_size,
	.fill_info	= can_fill_info,
	.get_xstats_size = can_get_xstats_size,
	.fill_xstats	= can_fill_xstats,
};

int can_netlink_register(void)
{
	return rtnl_link_register(&can_link_ops);
}

void can_netlink_unregister(void)
{
	rtnl_link_unregister(&can_link_ops);
}
