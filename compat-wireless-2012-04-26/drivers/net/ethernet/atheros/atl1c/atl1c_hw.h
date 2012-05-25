/*
 * Copyright(c) 2008 - 2009 Atheros Corporation. All rights reserved.
 *
 * Derived from Intel e1000 driver
 * Copyright(c) 1999 - 2005 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ATL1C_HW_H_
#define _ATL1C_HW_H_

#include <linux/types.h>
#include <linux/mii.h>

#define FIELD_GETX(_x, _name)   ((_x) >> (_name##_SHIFT) & (_name##_MASK))
#define FIELD_SETX(_x, _name, _v) \
(((_x) & ~((_name##_MASK) << (_name##_SHIFT))) |\
(((_v) & (_name##_MASK)) << (_name##_SHIFT)))
#define FIELDX(_name, _v) (((_v) & (_name##_MASK)) << (_name##_SHIFT))

struct atl1c_adapter;
struct atl1c_hw;

/* function prototype */
void atl1c_phy_disable(struct atl1c_hw *hw);
void atl1c_hw_set_mac_addr(struct atl1c_hw *hw);
int atl1c_phy_reset(struct atl1c_hw *hw);
int atl1c_read_mac_addr(struct atl1c_hw *hw);
int atl1c_get_speed_and_duplex(struct atl1c_hw *hw, u16 *speed, u16 *duplex);
u32 atl1c_hash_mc_addr(struct atl1c_hw *hw, u8 *mc_addr);
void atl1c_hash_set(struct atl1c_hw *hw, u32 hash_value);
int atl1c_read_phy_reg(struct atl1c_hw *hw, u16 reg_addr, u16 *phy_data);
int atl1c_write_phy_reg(struct atl1c_hw *hw, u32 reg_addr, u16 phy_data);
bool atl1c_read_eeprom(struct atl1c_hw *hw, u32 offset, u32 *p_value);
int atl1c_phy_init(struct atl1c_hw *hw);
int atl1c_check_eeprom_exist(struct atl1c_hw *hw);
int atl1c_restart_autoneg(struct atl1c_hw *hw);
int atl1c_phy_power_saving(struct atl1c_hw *hw);
/* register definition */
#define REG_DEVICE_CAP              	0x5C
#define DEVICE_CAP_MAX_PAYLOAD_MASK     0x7
#define DEVICE_CAP_MAX_PAYLOAD_SHIFT    0

#define DEVICE_CTRL_MAXRRS_MIN		2

#define REG_LINK_CTRL			0x68
#define LINK_CTRL_L0S_EN		0x01
#define LINK_CTRL_L1_EN			0x02
#define LINK_CTRL_EXT_SYNC		0x80

#define REG_DEV_SERIALNUM_CTRL		0x200
#define REG_DEV_MAC_SEL_MASK		0x0 /* 0:EUI; 1:MAC */
#define REG_DEV_MAC_SEL_SHIFT		0
#define REG_DEV_SERIAL_NUM_EN_MASK	0x1
#define REG_DEV_SERIAL_NUM_EN_SHIFT	1

#define REG_TWSI_CTRL               	0x218
#define TWSI_CTRL_LD_OFFSET_MASK        0xFF
#define TWSI_CTRL_LD_OFFSET_SHIFT       0
#define TWSI_CTRL_LD_SLV_ADDR_MASK      0x7
#define TWSI_CTRL_LD_SLV_ADDR_SHIFT     8
#define TWSI_CTRL_SW_LDSTART            0x800
#define TWSI_CTRL_HW_LDSTART            0x1000
#define TWSI_CTRL_SMB_SLV_ADDR_MASK     0x7F
#define TWSI_CTRL_SMB_SLV_ADDR_SHIFT    15
#define TWSI_CTRL_LD_EXIST              0x400000
#define TWSI_CTRL_READ_FREQ_SEL_MASK    0x3
#define TWSI_CTRL_READ_FREQ_SEL_SHIFT   23
#define TWSI_CTRL_FREQ_SEL_100K         0
#define TWSI_CTRL_FREQ_SEL_200K         1
#define TWSI_CTRL_FREQ_SEL_300K         2
#define TWSI_CTRL_FREQ_SEL_400K         3
#define TWSI_CTRL_SMB_SLV_ADDR
#define TWSI_CTRL_WRITE_FREQ_SEL_MASK   0x3
#define TWSI_CTRL_WRITE_FREQ_SEL_SHIFT  24


#define REG_PCIE_DEV_MISC_CTRL      	0x21C
#define PCIE_DEV_MISC_EXT_PIPE     	0x2
#define PCIE_DEV_MISC_RETRY_BUFDIS 	0x1
#define PCIE_DEV_MISC_SPIROM_EXIST 	0x4
#define PCIE_DEV_MISC_SERDES_ENDIAN    	0x8
#define PCIE_DEV_MISC_SERDES_SEL_DIN   	0x10

#define REG_PCIE_PHYMISC	    	0x1000
#define PCIE_PHYMISC_FORCE_RCV_DET	BIT(2)
#define PCIE_PHYMISC_NFTS_MASK		0xFFUL
#define PCIE_PHYMISC_NFTS_SHIFT		16

#define REG_PCIE_PHYMISC2		0x1004
#define PCIE_PHYMISC2_L0S_TH_MASK	0x3UL
#define PCIE_PHYMISC2_L0S_TH_SHIFT	18
#define L2CB1_PCIE_PHYMISC2_L0S_TH	3
#define PCIE_PHYMISC2_CDR_BW_MASK	0x3UL
#define PCIE_PHYMISC2_CDR_BW_SHIFT	16
#define L2CB1_PCIE_PHYMISC2_CDR_BW	3

#define REG_TWSI_DEBUG			0x1108
#define TWSI_DEBUG_DEV_EXIST		0x20000000

#define REG_DMA_DBG			0x1114
#define DMA_DBG_VENDOR_MSG		BIT(0)

#define REG_EEPROM_CTRL			0x12C0
#define EEPROM_CTRL_DATA_HI_MASK	0xFFFF
#define EEPROM_CTRL_DATA_HI_SHIFT	0
#define EEPROM_CTRL_ADDR_MASK		0x3FF
#define EEPROM_CTRL_ADDR_SHIFT		16
#define EEPROM_CTRL_ACK			0x40000000
#define EEPROM_CTRL_RW			0x80000000

#define REG_EEPROM_DATA_LO		0x12C4

#define REG_OTP_CTRL			0x12F0
#define OTP_CTRL_CLK_EN			0x0002

#define REG_PM_CTRL			0x12F8
#define PM_CTRL_HOTRST			BIT(31)
#define PM_CTRL_MAC_ASPM_CHK		BIT(30)	/* L0s/L1 dis by MAC based on
						 * thrghput(setting in 15A0) */
#define PM_CTRL_SA_DLY_EN		BIT(29)
#define PM_CTRL_L0S_BUFSRX_EN		BIT(28)
#define PM_CTRL_LCKDET_TIMER_MASK	0xFUL
#define PM_CTRL_LCKDET_TIMER_SHIFT	24
#define PM_CTRL_LCKDET_TIMER_DEF	0xC
#define PM_CTRL_PM_REQ_TIMER_MASK	0xFUL
#define PM_CTRL_PM_REQ_TIMER_SHIFT	20	/* pm_request_l1 time > @
						 * ->L0s not L1 */
#define PM_CTRL_PM_REQ_TO_DEF		0xC
#define PMCTRL_TXL1_AFTER_L0S		BIT(19)	/* l1dv2.0+ */
#define L1D_PMCTRL_L1_ENTRY_TM_MASK	7UL	/* l1dv2.0+, 3bits */
#define L1D_PMCTRL_L1_ENTRY_TM_SHIFT	16
#define L1D_PMCTRL_L1_ENTRY_TM_DIS	0
#define L1D_PMCTRL_L1_ENTRY_TM_2US	1
#define L1D_PMCTRL_L1_ENTRY_TM_4US	2
#define L1D_PMCTRL_L1_ENTRY_TM_8US	3
#define L1D_PMCTRL_L1_ENTRY_TM_16US	4
#define L1D_PMCTRL_L1_ENTRY_TM_24US	5
#define L1D_PMCTRL_L1_ENTRY_TM_32US	6
#define L1D_PMCTRL_L1_ENTRY_TM_63US	7
#define PM_CTRL_L1_ENTRY_TIMER_MASK	0xFUL  /* l1C 4bits */
#define PM_CTRL_L1_ENTRY_TIMER_SHIFT	16
#define L2CB1_PM_CTRL_L1_ENTRY_TM	7
#define L1C_PM_CTRL_L1_ENTRY_TM		0xF
#define PM_CTRL_RCVR_WT_TIMER		BIT(15)	/* 1:1us, 0:2ms */
#define PM_CTRL_CLK_PWM_VER1_1		BIT(14)	/* 0:1.0a,1:1.1 */
#define PM_CTRL_CLK_SWH_L1		BIT(13)	/* en pcie clk sw in L1 */
#define PM_CTRL_ASPM_L0S_EN		BIT(12)
#define PM_CTRL_RXL1_AFTER_L0S		BIT(11)	/* l1dv2.0+ */
#define L1D_PMCTRL_L0S_TIMER_MASK	7UL	/* l1d2.0+, 3bits*/
#define L1D_PMCTRL_L0S_TIMER_SHIFT	8
#define PM_CTRL_L0S_ENTRY_TIMER_MASK	0xFUL	/* l1c, 4bits */
#define PM_CTRL_L0S_ENTRY_TIMER_SHIFT	8
#define PM_CTRL_SERDES_BUFS_RX_L1_EN	BIT(7)
#define PM_CTRL_SERDES_PD_EX_L1		BIT(6)	/* power down serdes rx */
#define PM_CTRL_SERDES_PLL_L1_EN	BIT(5)
#define PM_CTRL_SERDES_L1_EN		BIT(4)
#define PM_CTRL_ASPM_L1_EN		BIT(3)
#define PM_CTRL_CLK_REQ_EN		BIT(2)
#define PM_CTRL_RBER_EN			BIT(1)
#define PM_CTRL_SPRSDWER_EN		BIT(0)

#define REG_LTSSM_ID_CTRL		0x12FC
#define LTSSM_ID_EN_WRO			0x1000


/* Selene Master Control Register */
#define REG_MASTER_CTRL			0x1400
#define MASTER_CTRL_OTP_SEL		BIT(31)
#define MASTER_DEV_NUM_MASK		0x7FUL
#define MASTER_DEV_NUM_SHIFT		24
#define MASTER_REV_NUM_MASK		0xFFUL
#define MASTER_REV_NUM_SHIFT		16
#define MASTER_CTRL_INT_RDCLR		BIT(14)
#define MASTER_CTRL_CLK_SEL_DIS		BIT(12)	/* 1:alwys sel pclk from
						 * serdes, not sw to 25M */
#define MASTER_CTRL_RX_ITIMER_EN	BIT(11)	/* IRQ MODURATION FOR RX */
#define MASTER_CTRL_TX_ITIMER_EN	BIT(10)	/* MODURATION FOR TX/RX */
#define MASTER_CTRL_MANU_INT		BIT(9)	/* SOFT MANUAL INT */
#define MASTER_CTRL_MANUTIMER_EN	BIT(8)
#define MASTER_CTRL_SA_TIMER_EN		BIT(7)	/* SYS ALIVE TIMER EN */
#define MASTER_CTRL_OOB_DIS		BIT(6)	/* OUT OF BOX DIS */
#define MASTER_CTRL_WAKEN_25M		BIT(5)	/* WAKE WO. PCIE CLK */
#define MASTER_CTRL_BERT_START		BIT(4)
#define MASTER_PCIE_TSTMOD_MASK		3UL
#define MASTER_PCIE_TSTMOD_SHIFT	2
#define MASTER_PCIE_RST			BIT(1)
#define MASTER_CTRL_SOFT_RST		BIT(0)	/* RST MAC & DMA */
#define DMA_MAC_RST_TO			50

/* Timer Initial Value Register */
#define REG_MANUAL_TIMER_INIT       	0x1404

/* IRQ ModeratorTimer Initial Value Register */
#define REG_IRQ_MODRT_TIMER_INIT     	0x1408
#define IRQ_MODRT_TIMER_MASK		0xffff
#define IRQ_MODRT_TX_TIMER_SHIFT    	0
#define IRQ_MODRT_RX_TIMER_SHIFT	16

#define REG_GPHY_CTRL               	0x140C
#define GPHY_CTRL_EXT_RESET         	0x1
#define GPHY_CTRL_RTL_MODE		0x2
#define GPHY_CTRL_LED_MODE		0x4
#define GPHY_CTRL_ANEG_NOW		0x8
#define GPHY_CTRL_REV_ANEG		0x10
#define GPHY_CTRL_GATE_25M_EN       	0x20
#define GPHY_CTRL_LPW_EXIT          	0x40
#define GPHY_CTRL_PHY_IDDQ          	0x80
#define GPHY_CTRL_PHY_IDDQ_DIS      	0x100
#define GPHY_CTRL_GIGA_DIS		0x200
#define GPHY_CTRL_HIB_EN            	0x400
#define GPHY_CTRL_HIB_PULSE         	0x800
#define GPHY_CTRL_SEL_ANA_RST       	0x1000
#define GPHY_CTRL_PHY_PLL_ON        	0x2000
#define GPHY_CTRL_PWDOWN_HW		0x4000
#define GPHY_CTRL_PHY_PLL_BYPASS	0x8000

#define GPHY_CTRL_DEFAULT (		 \
		GPHY_CTRL_SEL_ANA_RST	|\
		GPHY_CTRL_HIB_PULSE	|\
		GPHY_CTRL_HIB_EN)

#define GPHY_CTRL_PW_WOL_DIS (		 \
		GPHY_CTRL_SEL_ANA_RST	|\
		GPHY_CTRL_HIB_PULSE	|\
		GPHY_CTRL_HIB_EN	|\
		GPHY_CTRL_PWDOWN_HW	|\
		GPHY_CTRL_PHY_IDDQ)

#define GPHY_CTRL_POWER_SAVING (	\
		GPHY_CTRL_SEL_ANA_RST	|\
		GPHY_CTRL_HIB_EN	|\
		GPHY_CTRL_HIB_PULSE	|\
		GPHY_CTRL_PWDOWN_HW	|\
		GPHY_CTRL_PHY_IDDQ)

/* Block IDLE Status Register */
#define REG_IDLE_STATUS			0x1410
#define IDLE_STATUS_SFORCE_MASK		0xFUL
#define IDLE_STATUS_SFORCE_SHIFT	14
#define IDLE_STATUS_CALIB_DONE		BIT(13)
#define IDLE_STATUS_CALIB_RES_MASK	0x1FUL
#define IDLE_STATUS_CALIB_RES_SHIFT	8
#define IDLE_STATUS_CALIBERR_MASK	0xFUL
#define IDLE_STATUS_CALIBERR_SHIFT	4
#define IDLE_STATUS_TXQ_BUSY		BIT(3)
#define IDLE_STATUS_RXQ_BUSY		BIT(2)
#define IDLE_STATUS_TXMAC_BUSY		BIT(1)
#define IDLE_STATUS_RXMAC_BUSY		BIT(0)
#define IDLE_STATUS_MASK		(\
	IDLE_STATUS_TXQ_BUSY		|\
	IDLE_STATUS_RXQ_BUSY		|\
	IDLE_STATUS_TXMAC_BUSY		|\
	IDLE_STATUS_RXMAC_BUSY)

/* MDIO Control Register */
#define REG_MDIO_CTRL           	0x1414
#define MDIO_DATA_MASK          	0xffff  /* On MDIO write, the 16-bit
						 * control data to write to PHY
						 * MII management register */
#define MDIO_DATA_SHIFT         	0       /* On MDIO read, the 16-bit
						 * status data that was read
						 * from the PHY MII management register */
#define MDIO_REG_ADDR_MASK      	0x1f    /* MDIO register address */
#define MDIO_REG_ADDR_SHIFT     	16
#define MDIO_RW                 	0x200000  /* 1: read, 0: write */
#define MDIO_SUP_PREAMBLE       	0x400000  /* Suppress preamble */
#define MDIO_START              	0x800000  /* Write 1 to initiate the MDIO
						   * master. And this bit is self
						   * cleared after one cycle */
#define MDIO_CLK_SEL_SHIFT      	24
#define MDIO_CLK_25_4           	0
#define MDIO_CLK_25_6           	2
#define MDIO_CLK_25_8           	3
#define MDIO_CLK_25_10          	4
#define MDIO_CLK_25_14          	5
#define MDIO_CLK_25_20          	6
#define MDIO_CLK_25_28          	7
#define MDIO_BUSY               	0x8000000
#define MDIO_AP_EN              	0x10000000
#define MDIO_WAIT_TIMES         	10

/* MII PHY Status Register */
#define REG_PHY_STATUS           	0x1418
#define PHY_GENERAL_STATUS_MASK		0xFFFF
#define PHY_STATUS_RECV_ENABLE		0x0001
#define PHY_OE_PWSP_STATUS_MASK		0x07FF
#define PHY_OE_PWSP_STATUS_SHIFT	16
#define PHY_STATUS_LPW_STATE		0x80000000
/* BIST Control and Status Register0 (for the Packet Memory) */
#define REG_BIST0_CTRL              	0x141c
#define BIST0_NOW                   	0x1
#define BIST0_SRAM_FAIL             	0x2 /* 1: The SRAM failure is
					     * un-repairable  because
					     * it has address decoder
					     * failure or more than 1 cell
					     * stuck-to-x failure */
#define BIST0_FUSE_FLAG             	0x4

/* BIST Control and Status Register1(for the retry buffer of PCI Express) */
#define REG_BIST1_CTRL			0x1420
#define BIST1_NOW                   	0x1
#define BIST1_SRAM_FAIL             	0x2
#define BIST1_FUSE_FLAG             	0x4

/* SerDes Lock Detect Control and Status Register */
#define REG_SERDES_LOCK            	0x1424
#define SERDES_LOCK_DETECT          	0x1  /* SerDes lock detected. This signal
					      * comes from Analog SerDes */
#define SERDES_LOCK_DETECT_EN       	0x2  /* 1: Enable SerDes Lock detect function */
#define SERDES_LOCK_STS_SELFB_PLL_SHIFT 0xE
#define SERDES_LOCK_STS_SELFB_PLL_MASK  0x3
#define SERDES_OVCLK_18_25		0x0
#define SERDES_OVCLK_12_18		0x1
#define SERDES_OVCLK_0_4		0x2
#define SERDES_OVCLK_4_12		0x3
#define SERDES_MAC_CLK_SLOWDOWN		0x20000
#define SERDES_PYH_CLK_SLOWDOWN		0x40000

/* MAC Control Register  */
#define REG_MAC_CTRL         		0x1480
#define MAC_CTRL_TX_EN			0x1
#define MAC_CTRL_RX_EN			0x2
#define MAC_CTRL_TX_FLOW		0x4
#define MAC_CTRL_RX_FLOW            	0x8
#define MAC_CTRL_LOOPBACK          	0x10
#define MAC_CTRL_DUPLX              	0x20
#define MAC_CTRL_ADD_CRC            	0x40
#define MAC_CTRL_PAD                	0x80
#define MAC_CTRL_LENCHK             	0x100
#define MAC_CTRL_HUGE_EN            	0x200
#define MAC_CTRL_PRMLEN_SHIFT       	10
#define MAC_CTRL_PRMLEN_MASK        	0xf
#define MAC_CTRL_RMV_VLAN           	0x4000
#define MAC_CTRL_PROMIS_EN          	0x8000
#define MAC_CTRL_TX_PAUSE           	0x10000
#define MAC_CTRL_SCNT               	0x20000
#define MAC_CTRL_SRST_TX            	0x40000
#define MAC_CTRL_TX_SIMURST         	0x80000
#define MAC_CTRL_SPEED_SHIFT        	20
#define MAC_CTRL_SPEED_MASK         	0x3
#define MAC_CTRL_DBG_TX_BKPRESURE   	0x400000
#define MAC_CTRL_TX_HUGE            	0x800000
#define MAC_CTRL_RX_CHKSUM_EN       	0x1000000
#define MAC_CTRL_MC_ALL_EN          	0x2000000
#define MAC_CTRL_BC_EN              	0x4000000
#define MAC_CTRL_DBG                	0x8000000
#define MAC_CTRL_SINGLE_PAUSE_EN	0x10000000
#define MAC_CTRL_HASH_ALG_CRC32		0x20000000
#define MAC_CTRL_SPEED_MODE_SW		0x40000000

/* MAC IPG/IFG Control Register  */
#define REG_MAC_IPG_IFG             	0x1484
#define MAC_IPG_IFG_IPGT_SHIFT      	0 	/* Desired back to back
						 * inter-packet gap. The
						 * default is 96-bit time */
#define MAC_IPG_IFG_IPGT_MASK       	0x7f
#define MAC_IPG_IFG_MIFG_SHIFT      	8       /* Minimum number of IFG to
						 * enforce in between RX frames */
#define MAC_IPG_IFG_MIFG_MASK       	0xff  	/* Frame gap below such IFP is dropped */
#define MAC_IPG_IFG_IPGR1_SHIFT     	16   	/* 64bit Carrier-Sense window */
#define MAC_IPG_IFG_IPGR1_MASK      	0x7f
#define MAC_IPG_IFG_IPGR2_SHIFT     	24    	/* 96-bit IPG window */
#define MAC_IPG_IFG_IPGR2_MASK      	0x7f

/* MAC STATION ADDRESS  */
#define REG_MAC_STA_ADDR		0x1488

/* Hash table for multicast address */
#define REG_RX_HASH_TABLE		0x1490

/* MAC Half-Duplex Control Register */
#define REG_MAC_HALF_DUPLX_CTRL     	0x1498
#define MAC_HALF_DUPLX_CTRL_LCOL_SHIFT  0      /* Collision Window */
#define MAC_HALF_DUPLX_CTRL_LCOL_MASK   0x3ff
#define MAC_HALF_DUPLX_CTRL_RETRY_SHIFT 12
#define MAC_HALF_DUPLX_CTRL_RETRY_MASK  0xf
#define MAC_HALF_DUPLX_CTRL_EXC_DEF_EN  0x10000
#define MAC_HALF_DUPLX_CTRL_NO_BACK_C   0x20000
#define MAC_HALF_DUPLX_CTRL_NO_BACK_P   0x40000 /* No back-off on backpressure,
						 * immediately start the
						 * transmission after back pressure */
#define MAC_HALF_DUPLX_CTRL_ABEBE        0x80000 /* 1: Alternative Binary Exponential Back-off Enabled */
#define MAC_HALF_DUPLX_CTRL_ABEBT_SHIFT  20      /* Maximum binary exponential number */
#define MAC_HALF_DUPLX_CTRL_ABEBT_MASK   0xf
#define MAC_HALF_DUPLX_CTRL_JAMIPG_SHIFT 24      /* IPG to start JAM for collision based flow control in half-duplex */
#define MAC_HALF_DUPLX_CTRL_JAMIPG_MASK  0xf     /* mode. In unit of 8-bit time */

/* Maximum Frame Length Control Register   */
#define REG_MTU                     	0x149c

/* Wake-On-Lan control register */
#define REG_WOL_CTRL                	0x14a0
#define WOL_PT7_MATCH			BIT(31)
#define WOL_PT6_MATCH			BIT(30)
#define WOL_PT5_MATCH			BIT(29)
#define WOL_PT4_MATCH			BIT(28)
#define WOL_PT3_MATCH			BIT(27)
#define WOL_PT2_MATCH			BIT(26)
#define WOL_PT1_MATCH			BIT(25)
#define WOL_PT0_MATCH			BIT(24)
#define WOL_PT7_EN			BIT(23)
#define WOL_PT6_EN			BIT(22)
#define WOL_PT5_EN			BIT(21)
#define WOL_PT4_EN			BIT(20)
#define WOL_PT3_EN			BIT(19)
#define WOL_PT2_EN			BIT(18)
#define WOL_PT1_EN			BIT(17)
#define WOL_PT0_EN			BIT(16)
#define WOL_LNKCHG_ST			BIT(10)
#define WOL_MAGIC_ST			BIT(9)
#define WOL_PATTERN_ST			BIT(8)
#define WOL_OOB_EN			BIT(6)
#define WOL_LINK_CHG_PME_EN		BIT(5)
#define WOL_LINK_CHG_EN			BIT(4)
#define WOL_MAGIC_PME_EN		BIT(3)
#define WOL_MAGIC_EN			BIT(2)
#define WOL_PATTERN_PME_EN		BIT(1)
#define WOL_PATTERN_EN			BIT(0)

/* WOL Length ( 2 DWORD ) */
#define REG_WOL_PTLEN1			0x14A4
#define WOL_PTLEN1_3_MASK		0xFFUL
#define WOL_PTLEN1_3_SHIFT		24
#define WOL_PTLEN1_2_MASK		0xFFUL
#define WOL_PTLEN1_2_SHIFT		16
#define WOL_PTLEN1_1_MASK		0xFFUL
#define WOL_PTLEN1_1_SHIFT		8
#define WOL_PTLEN1_0_MASK		0xFFUL
#define WOL_PTLEN1_0_SHIFT		0

#define REG_WOL_PTLEN2			0x14A8
#define WOL_PTLEN2_7_MASK		0xFFUL
#define WOL_PTLEN2_7_SHIFT		24
#define WOL_PTLEN2_6_MASK		0xFFUL
#define WOL_PTLEN2_6_SHIFT		16
#define WOL_PTLEN2_5_MASK		0xFFUL
#define WOL_PTLEN2_5_SHIFT		8
#define WOL_PTLEN2_4_MASK		0xFFUL
#define WOL_PTLEN2_4_SHIFT		0

/* Internal SRAM Partition Register */
#define RFDX_HEAD_ADDR_MASK		0x03FF
#define RFDX_HARD_ADDR_SHIFT		0
#define RFDX_TAIL_ADDR_MASK		0x03FF
#define RFDX_TAIL_ADDR_SHIFT            16

#define REG_SRAM_RFD0_INFO		0x1500
#define REG_SRAM_RFD1_INFO		0x1504
#define REG_SRAM_RFD2_INFO		0x1508
#define	REG_SRAM_RFD3_INFO		0x150C

#define REG_RFD_NIC_LEN			0x1510 /* In 8-bytes */
#define RFD_NIC_LEN_MASK		0x03FF

#define REG_SRAM_TRD_ADDR           	0x1518
#define TPD_HEAD_ADDR_MASK		0x03FF
#define TPD_HEAD_ADDR_SHIFT		0
#define TPD_TAIL_ADDR_MASK		0x03FF
#define TPD_TAIL_ADDR_SHIFT		16

#define REG_SRAM_TRD_LEN            	0x151C /* In 8-bytes */
#define TPD_NIC_LEN_MASK		0x03FF

#define REG_SRAM_RXF_ADDR          	0x1520
#define REG_SRAM_RXF_LEN            	0x1524
#define REG_SRAM_TXF_ADDR           	0x1528
#define REG_SRAM_TXF_LEN            	0x152C
#define REG_SRAM_TCPH_ADDR          	0x1530
#define REG_SRAM_PKTH_ADDR          	0x1532

/*
 * Load Ptr Register
 * Software sets this bit after the initialization of the head and tail */
#define REG_LOAD_PTR                	0x1534

/*
 * addresses of all descriptors, as well as the following descriptor
 * control register, which triggers each function block to load the head
 * pointer to prepare for the operation. This bit is then self-cleared
 * after one cycle.
 */
#define REG_RX_BASE_ADDR_HI		0x1540
#define REG_TX_BASE_ADDR_HI		0x1544
#define REG_RFD0_HEAD_ADDR_LO		0x1550
#define REG_RFD_RING_SIZE		0x1560
#define RFD_RING_SIZE_MASK		0x0FFF
#define REG_RX_BUF_SIZE			0x1564
#define RX_BUF_SIZE_MASK		0xFFFF
#define REG_RRD0_HEAD_ADDR_LO		0x1568
#define REG_RRD_RING_SIZE		0x1578
#define RRD_RING_SIZE_MASK		0x0FFF
#define REG_TPD_PRI1_ADDR_LO		0x157C
#define REG_TPD_PRI0_ADDR_LO		0x1580
#define REG_TPD_RING_SIZE		0x1584
#define TPD_RING_SIZE_MASK		0xFFFF

/* TXQ Control Register */
#define REG_TXQ_CTRL			0x1590
#define TXQ_TXF_BURST_NUM_MASK          0xFFFFUL
#define TXQ_TXF_BURST_NUM_SHIFT		16
#define L1C_TXQ_TXF_BURST_PREF          0x200
#define L2CB_TXQ_TXF_BURST_PREF         0x40
#define TXQ_CTRL_PEDING_CLR             BIT(8)
#define TXQ_CTRL_LS_8023_EN             BIT(7)
#define TXQ_CTRL_ENH_MODE               BIT(6)
#define TXQ_CTRL_EN                     BIT(5)
#define TXQ_CTRL_IP_OPTION_EN           BIT(4)
#define TXQ_NUM_TPD_BURST_MASK          0xFUL
#define TXQ_NUM_TPD_BURST_SHIFT         0
#define TXQ_NUM_TPD_BURST_DEF           5
#define TXQ_CFGV			(\
	FIELDX(TXQ_NUM_TPD_BURST, TXQ_NUM_TPD_BURST_DEF) |\
	TXQ_CTRL_ENH_MODE |\
	TXQ_CTRL_LS_8023_EN |\
	TXQ_CTRL_IP_OPTION_EN)
#define L1C_TXQ_CFGV			(\
	TXQ_CFGV |\
	FIELDX(TXQ_TXF_BURST_NUM, L1C_TXQ_TXF_BURST_PREF))
#define L2CB_TXQ_CFGV			(\
	TXQ_CFGV |\
	FIELDX(TXQ_TXF_BURST_NUM, L2CB_TXQ_TXF_BURST_PREF))


/* Jumbo packet Threshold for task offload */
#define REG_TX_TSO_OFFLOAD_THRESH	0x1594 /* In 8-bytes */
#define TX_TSO_OFFLOAD_THRESH_MASK	0x07FF
#define MAX_TSO_FRAME_SIZE		(7*1024)

#define	REG_TXF_WATER_MARK		0x1598 /* In 8-bytes */
#define TXF_WATER_MARK_MASK		0x0FFF
#define TXF_LOW_WATER_MARK_SHIFT	0
#define TXF_HIGH_WATER_MARK_SHIFT 	16
#define TXQ_CTRL_BURST_MODE_EN		0x80000000

#define REG_THRUPUT_MON_CTRL		0x159C
#define THRUPUT_MON_RATE_MASK		0x3
#define THRUPUT_MON_RATE_SHIFT		0
#define THRUPUT_MON_EN			0x80

/* RXQ Control Register */
#define REG_RXQ_CTRL                	0x15A0
#define ASPM_THRUPUT_LIMIT_MASK		0x3
#define ASPM_THRUPUT_LIMIT_SHIFT	0
#define ASPM_THRUPUT_LIMIT_NO		0x00
#define ASPM_THRUPUT_LIMIT_1M		0x01
#define ASPM_THRUPUT_LIMIT_10M		0x02
#define ASPM_THRUPUT_LIMIT_100M		0x03
#define IPV6_CHKSUM_CTRL_EN		BIT(7)
#define RXQ_RFD_BURST_NUM_MASK		0x003F
#define RXQ_RFD_BURST_NUM_SHIFT		20
#define RXQ_NUM_RFD_PREF_DEF		8
#define RSS_MODE_MASK			3UL
#define RSS_MODE_SHIFT			26
#define RSS_MODE_DIS			0
#define RSS_MODE_SQSI			1
#define RSS_MODE_MQSI			2
#define RSS_MODE_MQMI			3
#define RSS_NIP_QUEUE_SEL		BIT(28) /* 0:q0, 1:table */
#define RRS_HASH_CTRL_EN		BIT(29)
#define RX_CUT_THRU_EN			BIT(30)
#define RXQ_CTRL_EN			BIT(31)

#define REG_RFD_FREE_THRESH		0x15A4
#define RFD_FREE_THRESH_MASK		0x003F
#define RFD_FREE_HI_THRESH_SHIFT	0
#define RFD_FREE_LO_THRESH_SHIFT	6

/* RXF flow control register */
#define REG_RXQ_RXF_PAUSE_THRESH    	0x15A8
#define RXQ_RXF_PAUSE_TH_HI_SHIFT       0
#define RXQ_RXF_PAUSE_TH_HI_MASK        0x0FFF
#define RXQ_RXF_PAUSE_TH_LO_SHIFT       16
#define RXQ_RXF_PAUSE_TH_LO_MASK        0x0FFF

#define REG_RXD_DMA_CTRL		0x15AC
#define RXD_DMA_THRESH_MASK		0x0FFF	/* In 8-bytes */
#define RXD_DMA_THRESH_SHIFT		0
#define RXD_DMA_DOWN_TIMER_MASK		0xFFFF
#define RXD_DMA_DOWN_TIMER_SHIFT	16

/* DMA Engine Control Register */
#define REG_DMA_CTRL			0x15C0
#define DMA_CTRL_SMB_NOW                BIT(31)
#define DMA_CTRL_WPEND_CLR              BIT(30)
#define DMA_CTRL_RPEND_CLR              BIT(29)
#define DMA_CTRL_WDLY_CNT_MASK          0xFUL
#define DMA_CTRL_WDLY_CNT_SHIFT         16
#define DMA_CTRL_WDLY_CNT_DEF           4
#define DMA_CTRL_RDLY_CNT_MASK          0x1FUL
#define DMA_CTRL_RDLY_CNT_SHIFT         11
#define DMA_CTRL_RDLY_CNT_DEF           15
#define DMA_CTRL_RREQ_PRI_DATA          BIT(10)      /* 0:tpd, 1:data */
#define DMA_CTRL_WREQ_BLEN_MASK         7UL
#define DMA_CTRL_WREQ_BLEN_SHIFT        7
#define DMA_CTRL_RREQ_BLEN_MASK         7UL
#define DMA_CTRL_RREQ_BLEN_SHIFT        4
#define L1C_CTRL_DMA_RCB_LEN128         BIT(3)   /* 0:64bytes,1:128bytes */
#define DMA_CTRL_RORDER_MODE_MASK       7UL
#define DMA_CTRL_RORDER_MODE_SHIFT      0
#define DMA_CTRL_RORDER_MODE_OUT        4
#define DMA_CTRL_RORDER_MODE_ENHANCE    2
#define DMA_CTRL_RORDER_MODE_IN         1

/* INT-triggle/SMB Control Register */
#define REG_SMB_STAT_TIMER		0x15C4	/* 2us resolution */
#define SMB_STAT_TIMER_MASK		0xFFFFFF
#define REG_TINT_TPD_THRESH             0x15C8 /* tpd th to trig intrrupt */

/* Mail box */
#define MB_RFDX_PROD_IDX_MASK		0xFFFF
#define REG_MB_RFD0_PROD_IDX		0x15E0

#define REG_TPD_PRI1_PIDX               0x15F0	/* 16bit,hi-tpd producer idx */
#define REG_TPD_PRI0_PIDX		0x15F2	/* 16bit,lo-tpd producer idx */
#define REG_TPD_PRI1_CIDX		0x15F4	/* 16bit,hi-tpd consumer idx */
#define REG_TPD_PRI0_CIDX		0x15F6	/* 16bit,lo-tpd consumer idx */

#define REG_MB_RFD01_CONS_IDX		0x15F8
#define MB_RFD0_CONS_IDX_MASK		0x0000FFFF
#define MB_RFD1_CONS_IDX_MASK		0xFFFF0000

/* Interrupt Status Register */
#define REG_ISR    			0x1600
#define ISR_SMB				0x00000001
#define ISR_TIMER			0x00000002
/*
 * Software manual interrupt, for debug. Set when SW_MAN_INT_EN is set
 * in Table 51 Selene Master Control Register (Offset 0x1400).
 */
#define ISR_MANUAL         		0x00000004
#define ISR_HW_RXF_OV          		0x00000008 /* RXF overflow interrupt */
#define ISR_RFD0_UR			0x00000010 /* RFD0 under run */
#define ISR_RFD1_UR			0x00000020
#define ISR_RFD2_UR			0x00000040
#define ISR_RFD3_UR			0x00000080
#define ISR_TXF_UR			0x00000100
#define ISR_DMAR_TO_RST			0x00000200
#define ISR_DMAW_TO_RST			0x00000400
#define ISR_TX_CREDIT			0x00000800
#define ISR_GPHY			0x00001000
/* GPHY low power state interrupt */
#define ISR_GPHY_LPW           		0x00002000
#define ISR_TXQ_TO_RST			0x00004000
#define ISR_TX_PKT			0x00008000
#define ISR_RX_PKT_0			0x00010000
#define ISR_RX_PKT_1			0x00020000
#define ISR_RX_PKT_2			0x00040000
#define ISR_RX_PKT_3			0x00080000
#define ISR_MAC_RX			0x00100000
#define ISR_MAC_TX			0x00200000
#define ISR_UR_DETECTED			0x00400000
#define ISR_FERR_DETECTED		0x00800000
#define ISR_NFERR_DETECTED		0x01000000
#define ISR_CERR_DETECTED		0x02000000
#define ISR_PHY_LINKDOWN		0x04000000
#define ISR_DIS_INT			0x80000000

/* Interrupt Mask Register */
#define REG_IMR				0x1604

#define IMR_NORMAL_MASK		(\
		ISR_MANUAL	|\
		ISR_HW_RXF_OV	|\
		ISR_RFD0_UR	|\
		ISR_TXF_UR	|\
		ISR_DMAR_TO_RST	|\
		ISR_TXQ_TO_RST  |\
		ISR_DMAW_TO_RST	|\
		ISR_GPHY	|\
		ISR_TX_PKT	|\
		ISR_RX_PKT_0	|\
		ISR_GPHY_LPW    |\
		ISR_PHY_LINKDOWN)

#define ISR_RX_PKT 	(\
	ISR_RX_PKT_0    |\
	ISR_RX_PKT_1    |\
	ISR_RX_PKT_2    |\
	ISR_RX_PKT_3)

#define ISR_OVER	(\
	ISR_RFD0_UR 	|\
	ISR_RFD1_UR	|\
	ISR_RFD2_UR	|\
	ISR_RFD3_UR	|\
	ISR_HW_RXF_OV	|\
	ISR_TXF_UR)

#define ISR_ERROR	(\
	ISR_DMAR_TO_RST	|\
	ISR_TXQ_TO_RST  |\
	ISR_DMAW_TO_RST	|\
	ISR_PHY_LINKDOWN)

#define REG_INT_RETRIG_TIMER		0x1608
#define INT_RETRIG_TIMER_MASK		0xFFFF

#define REG_MAC_RX_STATUS_BIN 		0x1700
#define REG_MAC_RX_STATUS_END 		0x175c
#define REG_MAC_TX_STATUS_BIN 		0x1760
#define REG_MAC_TX_STATUS_END 		0x17c0

#define REG_CLK_GATING_CTRL		0x1814
#define CLK_GATING_DMAW_EN		0x0001
#define CLK_GATING_DMAR_EN		0x0002
#define CLK_GATING_TXQ_EN		0x0004
#define CLK_GATING_RXQ_EN		0x0008
#define CLK_GATING_TXMAC_EN		0x0010
#define CLK_GATING_RXMAC_EN		0x0020

#define CLK_GATING_EN_ALL	(CLK_GATING_DMAW_EN |\
				 CLK_GATING_DMAR_EN |\
				 CLK_GATING_TXQ_EN  |\
				 CLK_GATING_RXQ_EN  |\
				 CLK_GATING_TXMAC_EN|\
				 CLK_GATING_RXMAC_EN)

/* DEBUG ADDR */
#define REG_DEBUG_DATA0 		0x1900
#define REG_DEBUG_DATA1 		0x1904

#define L1D_MPW_PHYID1			0xD01C  /* V7 */
#define L1D_MPW_PHYID2			0xD01D  /* V1-V6 */
#define L1D_MPW_PHYID3			0xD01E  /* V8 */


/* Autoneg Advertisement Register */
#define ADVERTISE_DEFAULT_CAP \
	(ADVERTISE_ALL | ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM)

/* 1000BASE-T Control Register */
#define GIGA_CR_1000T_REPEATER_DTE	0x0400  /* 1=Repeater/switch device port 0=DTE device */

#define GIGA_CR_1000T_MS_VALUE		0x0800  /* 1=Configure PHY as Master 0=Configure PHY as Slave */
#define GIGA_CR_1000T_MS_ENABLE		0x1000  /* 1=Master/Slave manual config value 0=Automatic Master/Slave config */
#define GIGA_CR_1000T_TEST_MODE_NORMAL	0x0000  /* Normal Operation */
#define GIGA_CR_1000T_TEST_MODE_1	0x2000  /* Transmit Waveform test */
#define GIGA_CR_1000T_TEST_MODE_2	0x4000  /* Master Transmit Jitter test */
#define GIGA_CR_1000T_TEST_MODE_3	0x6000  /* Slave Transmit Jitter test */
#define GIGA_CR_1000T_TEST_MODE_4	0x8000	/* Transmitter Distortion test */
#define GIGA_CR_1000T_SPEED_MASK	0x0300
#define GIGA_CR_1000T_DEFAULT_CAP	0x0300

/* PHY Specific Status Register */
#define MII_GIGA_PSSR			0x11
#define GIGA_PSSR_SPD_DPLX_RESOLVED	0x0800  /* 1=Speed & Duplex resolved */
#define GIGA_PSSR_DPLX			0x2000  /* 1=Duplex 0=Half Duplex */
#define GIGA_PSSR_SPEED			0xC000  /* Speed, bits 14:15 */
#define GIGA_PSSR_10MBS			0x0000  /* 00=10Mbs */
#define GIGA_PSSR_100MBS		0x4000  /* 01=100Mbs */
#define GIGA_PSSR_1000MBS		0x8000  /* 10=1000Mbs */

/* PHY Interrupt Enable Register */
#define MII_IER				0x12
#define IER_LINK_UP			0x0400
#define IER_LINK_DOWN			0x0800

/* PHY Interrupt Status Register */
#define MII_ISR				0x13
#define ISR_LINK_UP			0x0400
#define ISR_LINK_DOWN			0x0800

/* Cable-Detect-Test Control Register */
#define MII_CDTC			0x16
#define CDTC_EN_OFF			0   /* sc */
#define CDTC_EN_BITS			1
#define CDTC_PAIR_OFF			8
#define CDTC_PAIR_BIT			2

/* Cable-Detect-Test Status Register */
#define MII_CDTS			0x1C
#define CDTS_STATUS_OFF			8
#define CDTS_STATUS_BITS		2
#define CDTS_STATUS_NORMAL		0
#define CDTS_STATUS_SHORT		1
#define CDTS_STATUS_OPEN		2
#define CDTS_STATUS_INVALID		3

#define MII_DBG_ADDR			0x1D
#define MII_DBG_DATA			0x1E

#define MII_ANA_CTRL_0			0x0
#define ANA_RESTART_CAL			0x0001
#define ANA_MANUL_SWICH_ON_SHIFT	0x1
#define ANA_MANUL_SWICH_ON_MASK		0xF
#define ANA_MAN_ENABLE			0x0020
#define ANA_SEL_HSP			0x0040
#define ANA_EN_HB			0x0080
#define ANA_EN_HBIAS			0x0100
#define ANA_OEN_125M			0x0200
#define ANA_EN_LCKDT			0x0400
#define ANA_LCKDT_PHY			0x0800
#define ANA_AFE_MODE			0x1000
#define ANA_VCO_SLOW			0x2000
#define ANA_VCO_FAST			0x4000
#define ANA_SEL_CLK125M_DSP		0x8000

#define MII_ANA_CTRL_4			0x4
#define ANA_IECHO_ADJ_MASK		0xF
#define ANA_IECHO_ADJ_3_SHIFT		0
#define ANA_IECHO_ADJ_2_SHIFT		4
#define ANA_IECHO_ADJ_1_SHIFT		8
#define ANA_IECHO_ADJ_0_SHIFT		12

#define MII_ANA_CTRL_5			0x5
#define ANA_SERDES_CDR_BW_SHIFT		0
#define ANA_SERDES_CDR_BW_MASK		0x3
#define ANA_MS_PAD_DBG			0x0004
#define ANA_SPEEDUP_DBG			0x0008
#define ANA_SERDES_TH_LOS_SHIFT		4
#define ANA_SERDES_TH_LOS_MASK		0x3
#define ANA_SERDES_EN_DEEM		0x0040
#define ANA_SERDES_TXELECIDLE		0x0080
#define ANA_SERDES_BEACON		0x0100
#define ANA_SERDES_HALFTXDR		0x0200
#define ANA_SERDES_SEL_HSP		0x0400
#define ANA_SERDES_EN_PLL		0x0800
#define ANA_SERDES_EN			0x1000
#define ANA_SERDES_EN_LCKDT		0x2000

#define MII_ANA_CTRL_11			0xB
#define ANA_PS_HIB_EN			0x8000

#define MII_ANA_CTRL_18			0x12
#define ANA_TEST_MODE_10BT_01SHIFT	0
#define ANA_TEST_MODE_10BT_01MASK	0x3
#define ANA_LOOP_SEL_10BT		0x0004
#define ANA_RGMII_MODE_SW		0x0008
#define ANA_EN_LONGECABLE		0x0010
#define ANA_TEST_MODE_10BT_2		0x0020
#define ANA_EN_10BT_IDLE		0x0400
#define ANA_EN_MASK_TB			0x0800
#define ANA_TRIGGER_SEL_TIMER_SHIFT	12
#define ANA_TRIGGER_SEL_TIMER_MASK	0x3
#define ANA_INTERVAL_SEL_TIMER_SHIFT	14
#define ANA_INTERVAL_SEL_TIMER_MASK	0x3

#define MII_ANA_CTRL_41			0x29
#define ANA_TOP_PS_EN			0x8000

#define MII_ANA_CTRL_54			0x36
#define ANA_LONG_CABLE_TH_100_SHIFT	0
#define ANA_LONG_CABLE_TH_100_MASK	0x3F
#define ANA_DESERVED			0x0040
#define ANA_EN_LIT_CH			0x0080
#define ANA_SHORT_CABLE_TH_100_SHIFT	8
#define ANA_SHORT_CABLE_TH_100_MASK	0x3F
#define ANA_BP_BAD_LINK_ACCUM		0x4000
#define ANA_BP_SMALL_BW			0x8000

#endif /*_ATL1C_HW_H_*/
