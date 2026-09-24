// SPDX-License-Identifier: GPL-2.0-only
/*
 * STMicroelectronics ST21NFCD NFC controller, I2C transport
 *
 * The ST21NFCD speaks plain NCI over I2C: every frame, in both directions,
 * is an NCI packet with no link-layer framing around it. That is what sets
 * it apart from the ST21NFCB/C handled by st-nci, which wrap NCI in ST's
 * NDLC layer; an ST21NFCD given NDLC frames answers its reset notification
 * and then waits for a well-formed command that never comes.
 *
 * ST does not publish a datasheet for this part, so two values here were
 * established by observation on a Fairphone 4 rather than read from a spec,
 * and are marked as such where they are used: the 0x7e idle byte returned on
 * a read when the controller has nothing to send, and the proprietary RF
 * protocol number the controller reports for MIFARE Classic. Both are the
 * kind of thing a datasheet would pin down; corrections from anyone holding
 * one are welcome.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/skbuff.h>
#include <net/nfc/nci.h>
#include <net/nfc/nci_core.h>

/* Observed, not documented: returned as the first read byte when idle. */
#define ST21NFCD_IDLE_BYTE	0x7e

#define ST21NFCD_PROTOCOLS	(NFC_PROTO_JEWEL_MASK | \
				 NFC_PROTO_MIFARE_MASK | \
				 NFC_PROTO_FELICA_MASK | \
				 NFC_PROTO_ISO14443_MASK | \
				 NFC_PROTO_ISO14443_B_MASK | \
				 NFC_PROTO_ISO15693_MASK | \
				 NFC_PROTO_NFC_DEP_MASK)

struct st21nfcd {
	struct i2c_client *client;
	struct nci_dev *ndev;
	struct gpio_desc *reset;
	struct clk *clk;
};

static int st21nfcd_open(struct nci_dev *ndev)
{
	struct st21nfcd *phy = nci_get_drvdata(ndev);
	int ret;

	ret = clk_prepare_enable(phy->clk);
	if (ret)
		return ret;

	gpiod_set_value_cansleep(phy->reset, 0);
	/* The controller announces itself with CORE_RESET_NTF once out of reset */
	usleep_range(10000, 15000);

	return 0;
}

static int st21nfcd_close(struct nci_dev *ndev)
{
	struct st21nfcd *phy = nci_get_drvdata(ndev);

	gpiod_set_value_cansleep(phy->reset, 1);
	clk_disable_unprepare(phy->clk);

	return 0;
}

static int st21nfcd_send(struct nci_dev *ndev, struct sk_buff *skb)
{
	struct st21nfcd *phy = nci_get_drvdata(ndev);
	int ret;

	ret = i2c_master_send(phy->client, skb->data, skb->len);
	if (ret < 0) {
		/* The controller NACKs the first transfer when leaving standby */
		usleep_range(5000, 6000);
		ret = i2c_master_send(phy->client, skb->data, skb->len);
	}

	if (ret >= 0 && ret != skb->len)
		ret = -EREMOTEIO;
	if (ret < 0) {
		dev_err(&phy->client->dev, "I2C write failed: %d\n", ret);
		kfree_skb(skb);
		return ret;
	}

	consume_skb(skb);
	return 0;
}

/*
 * MIFARE Classic is not an NFC Forum protocol, so the controller reports it
 * with a proprietary RF protocol (and interface) value. The NCI core only
 * maps the standard ones and drops any target it cannot map, so without this
 * hook a MIFARE Classic card is activated and then discarded with "the target
 * found does not have the desired protocol".
 *
 * Observed, not documented: 0x90 for a MIFARE Classic 4K (SENS_RES 0x0002,
 * SEL_RES 0x18) on a Fairphone 4. This is the one value seen so far; other
 * MIFARE variants may report their own, which would be added here as they are
 * observed. st-nci maps its proprietary values the same way, for the same
 * reason (see st_nci_get_rfprotocol).
 */
#define ST21NFCD_RF_PROTOCOL_MIFARE_CLASSIC	0x90

static __u32 st21nfcd_get_rfprotocol(struct nci_dev *ndev, __u8 rf_protocol)
{
	return rf_protocol == ST21NFCD_RF_PROTOCOL_MIFARE_CLASSIC ?
		NFC_PROTO_MIFARE_MASK : 0;
}

static const struct nci_ops st21nfcd_nci_ops = {
	.open = st21nfcd_open,
	.close = st21nfcd_close,
	.send = st21nfcd_send,
	.get_rfprotocol = st21nfcd_get_rfprotocol,
};

static int st21nfcd_read(struct st21nfcd *phy, struct sk_buff **skb)
{
	struct nci_ctrl_hdr hdr;	/* same layout as a data header */
	int ret;

	ret = i2c_master_recv(phy->client, (u8 *)&hdr, NCI_CTRL_HDR_SIZE);
	if (ret < 0)
		return ret;
	if (ret != NCI_CTRL_HDR_SIZE)
		return -EBADMSG;
	if (hdr.gid == ST21NFCD_IDLE_BYTE)
		return -ENODATA;

	*skb = alloc_skb(NCI_CTRL_HDR_SIZE + hdr.plen, GFP_KERNEL);
	if (!*skb)
		return -ENOMEM;

	skb_put_data(*skb, &hdr, NCI_CTRL_HDR_SIZE);
	if (!hdr.plen)
		return 0;

	ret = i2c_master_recv(phy->client, skb_put(*skb, hdr.plen), hdr.plen);
	if (ret != hdr.plen) {
		kfree_skb(*skb);
		return ret < 0 ? ret : -EBADMSG;
	}

	return 0;
}

static irqreturn_t st21nfcd_irq_thread(int irq, void *data)
{
	struct st21nfcd *phy = data;
	struct sk_buff *skb = NULL;
	int ret;

	ret = st21nfcd_read(phy, &skb);
	/*
	 * -ENXIO: the line can assert as the controller leaves reset, before
	 * it answers on the bus. It raises the interrupt again once it has
	 * something to say.
	 */
	if (ret == -ENODATA || ret == -ENXIO)
		return IRQ_HANDLED;
	if (ret < 0) {
		dev_err_ratelimited(&phy->client->dev, "read failed: %d\n", ret);
		return IRQ_HANDLED;
	}

	nci_recv_frame(phy->ndev, skb);
	return IRQ_HANDLED;
}

static int st21nfcd_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct st21nfcd *phy;
	int ret;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
		return -ENODEV;

	phy = devm_kzalloc(dev, sizeof(*phy), GFP_KERNEL);
	if (!phy)
		return -ENOMEM;
	phy->client = client;
	i2c_set_clientdata(client, phy);

	phy->clk = devm_clk_get_optional(dev, NULL);
	if (IS_ERR(phy->clk))
		return dev_err_probe(dev, PTR_ERR(phy->clk),
				     "failed to get reference clock\n");

	/* Held in reset until the NFC core opens the device */
	phy->reset = devm_gpiod_get(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(phy->reset))
		return dev_err_probe(dev, PTR_ERR(phy->reset),
				     "failed to get reset GPIO\n");

	phy->ndev = nci_allocate_device(&st21nfcd_nci_ops, ST21NFCD_PROTOCOLS,
					0, 0);
	if (!phy->ndev)
		return -ENOMEM;
	nci_set_drvdata(phy->ndev, phy);

	ret = request_threaded_irq(client->irq, NULL, st21nfcd_irq_thread,
				   IRQF_ONESHOT, "st21nfcd", phy);
	if (ret) {
		dev_err_probe(dev, ret, "failed to request IRQ\n");
		goto err_free;
	}

	ret = nci_register_device(phy->ndev);
	if (ret) {
		dev_err_probe(dev, ret, "failed to register NCI device\n");
		goto err_irq;
	}

	return 0;

err_irq:
	free_irq(client->irq, phy);
err_free:
	nci_free_device(phy->ndev);
	return ret;
}

static void st21nfcd_remove(struct i2c_client *client)
{
	struct st21nfcd *phy = i2c_get_clientdata(client);

	nci_unregister_device(phy->ndev);
	free_irq(client->irq, phy);
	nci_free_device(phy->ndev);
}

static const struct of_device_id st21nfcd_of_match[] = {
	{ .compatible = "st,st21nfcd" },
	{ }
};
MODULE_DEVICE_TABLE(of, st21nfcd_of_match);

static const struct i2c_device_id st21nfcd_id[] = {
	{ "st21nfcd" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, st21nfcd_id);

static struct i2c_driver st21nfcd_driver = {
	.driver = {
		.name = "st21nfcd",
		.of_match_table = st21nfcd_of_match,
	},
	.probe = st21nfcd_probe,
	.remove = st21nfcd_remove,
	.id_table = st21nfcd_id,
};
module_i2c_driver(st21nfcd_driver);

MODULE_DESCRIPTION("STMicroelectronics ST21NFCD NFC controller I2C driver");
MODULE_LICENSE("GPL");
