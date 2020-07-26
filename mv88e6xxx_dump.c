#include <errno.h>
#include <getopt.h>
#include <linux/devlink.h>
#include <linux/genetlink.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mnlg.h"
#include "utils.h"

/* All single snapshots used by this program have this ID. */
#define SNAPSHOT_ID 42
#define MAX_SNAPSHOT_DATA 64 * 1024

#define MV88E6085	6085
#define MV88E6095	6095
#define MV88E6097	6097
#define MV88E6131	6131
#define MV88E6320	6320
#define MV88E6123	6123
#define MV88E6161	6161
#define MV88E6165	6165
#define MV88E6171	6171
#define MV88E6172	6172
#define MV88E6175	6175
#define MV88E6176	6176
#define MV88E6190	6190
#define MV88E6191	6191
#define MV88E6185	6185
#define MV88E6220	6220
#define MV88E6240	6240
#define MV88E6250	6250
#define MV88E6290	6290
#define MV88E6321	6321
#define MV88E6141	6141
#define MV88E6341	6341
#define MV88E6352	6352
#define MV88E6350	6350
#define MV88E6351	6351
#define MV88E6390	6390

#define MAX_PORTS 11

struct mv88e6xxx_ctx
{
	struct mnlg_socket *nlg;
	const char *bus_name;
	const char *dev_name;
	unsigned int chip;
	int ports;
	bool repeat;
	uint8_t snapshot_data[MAX_SNAPSHOT_DATA];
	size_t data_len;
	uint16_t port_regs[MAX_PORTS][32];
};

struct mv88e6xxx_devlink_atu_entry {
	/* The FID is scattered over multiple registers. */
	uint16_t fid;
	uint16_t atu_op;
	uint16_t atu_data;
	uint16_t atu_01;
	uint16_t atu_23;
	uint16_t atu_45;
};

void usage(const char *progname)
{
	printf("%s [OPTIONs]\n", progname);
	printf("  --debug/-d\tExtra debug output\n");
	printf("  --list/-l\tList the mv88e6xxx devices\n");
	printf("  --device/-d\tDump this device\n");
	printf("  --atu\t\tDump the ATU\n");
	printf("  --vtu\t\tDump the VTU\n");
	printf("  --ports\tDump all ports in a table\n");
	printf("  --global1\tDump global1 registers\n");
	printf("  --global2\tDump globAL2 registers\n");

	exit(EXIT_FAILURE);
}

static int _mnlg_socket_recv_run(struct mnlg_socket *nlg,
				 mnl_cb_t data_cb, void *data)
{
	int err;

	err = mnlg_socket_recv_run(nlg, data_cb, data);
	if (err < 0) {
		printf("devlink answers: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}

static int _mnlg_socket_send(struct mnlg_socket *nlg,
			     const struct nlmsghdr *nlh)
{
	int err;

	err = mnlg_socket_send(nlg, nlh);
	if (err < 0) {
		printf("Failed to call mnlg_socket_send\n");
		return -errno;
	}
	return 0;
}

static int _mnlg_socket_sndrcv(struct mnlg_socket *nlg,
			       const struct nlmsghdr *nlh,
			       mnl_cb_t data_cb, void *data)
{
	int err;

	err = _mnlg_socket_send(nlg, nlh);
	if (err)
		return err;

	return _mnlg_socket_recv_run(nlg, data_cb, data);
}

static const enum mnl_attr_data_type devlink_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_BUS_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_DEV_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_PORT_INDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_PORT_TYPE] = MNL_TYPE_U16,
	[DEVLINK_ATTR_PORT_DESIRED_TYPE] = MNL_TYPE_U16,
	[DEVLINK_ATTR_PORT_NETDEV_IFINDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_PORT_NETDEV_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_PORT_IBDEV_NAME] = MNL_TYPE_NUL_STRING,
	[DEVLINK_ATTR_SB_INDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_SIZE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_INGRESS_TC_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_EGRESS_TC_COUNT] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_POOL_INDEX] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_POOL_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_SB_POOL_SIZE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_SB_THRESHOLD] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_TC_INDEX] = MNL_TYPE_U16,
	[DEVLINK_ATTR_SB_OCC_CUR] = MNL_TYPE_U32,
	[DEVLINK_ATTR_SB_OCC_MAX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_ESWITCH_MODE] = MNL_TYPE_U16,
	[DEVLINK_ATTR_ESWITCH_INLINE_MODE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_ESWITCH_ENCAP_MODE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_DPIPE_TABLES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_DPIPE_TABLE_SIZE] = MNL_TYPE_U64,
	[DEVLINK_ATTR_DPIPE_TABLE_MATCHES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED] =  MNL_TYPE_U8,
	[DEVLINK_ATTR_DPIPE_ENTRIES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY_INDEX] = MNL_TYPE_U64,
	[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER] = MNL_TYPE_U64,
	[DEVLINK_ATTR_DPIPE_MATCH] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_MATCH_VALUE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_MATCH_TYPE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_ACTION] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ACTION_VALUE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_ACTION_TYPE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_VALUE_MAPPING] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_HEADERS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_HEADER] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_HEADER_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_DPIPE_HEADER_ID] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_HEADER_FIELDS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL] = MNL_TYPE_U8,
	[DEVLINK_ATTR_DPIPE_HEADER_INDEX] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_FIELD] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_DPIPE_FIELD_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_DPIPE_FIELD_ID] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH] = MNL_TYPE_U32,
	[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE] = MNL_TYPE_U32,
	[DEVLINK_ATTR_PARAM] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_PARAM_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_PARAM_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_PARAM_VALUES_LIST] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_PARAM_VALUE] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_PARAM_VALUE_CMODE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_REGION_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_REGION_SIZE] = MNL_TYPE_U64,
	[DEVLINK_ATTR_REGION_SNAPSHOTS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_SNAPSHOT] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_SNAPSHOT_ID] = MNL_TYPE_U32,
	[DEVLINK_ATTR_REGION_CHUNKS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_CHUNK] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_REGION_CHUNK_DATA] = MNL_TYPE_BINARY,
	[DEVLINK_ATTR_REGION_CHUNK_ADDR] = MNL_TYPE_U64,
	[DEVLINK_ATTR_REGION_CHUNK_LEN] = MNL_TYPE_U64,
	[DEVLINK_ATTR_INFO_DRIVER_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_INFO_SERIAL_NUMBER] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_INFO_VERSION_FIXED] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_INFO_VERSION_RUNNING] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_INFO_VERSION_STORED] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_INFO_VERSION_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_INFO_VERSION_VALUE] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_HEALTH_REPORTER] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_HEALTH_REPORTER_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_HEALTH_REPORTER_STATE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT] = MNL_TYPE_U64,
	[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT] = MNL_TYPE_U64,
	[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS] = MNL_TYPE_U64,
	[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD] = MNL_TYPE_U64,
	[DEVLINK_ATTR_FLASH_UPDATE_COMPONENT] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE] = MNL_TYPE_U64,
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL] = MNL_TYPE_U64,
	[DEVLINK_ATTR_STATS] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_TRAP_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_TRAP_ACTION] = MNL_TYPE_U8,
	[DEVLINK_ATTR_TRAP_TYPE] = MNL_TYPE_U8,
	[DEVLINK_ATTR_TRAP_GENERIC] = MNL_TYPE_FLAG,
	[DEVLINK_ATTR_TRAP_METADATA] = MNL_TYPE_NESTED,
	[DEVLINK_ATTR_TRAP_GROUP_NAME] = MNL_TYPE_STRING,
	[DEVLINK_ATTR_RELOAD_FAILED] = MNL_TYPE_U8,
};

static int attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	if (mnl_attr_type_valid(attr, DEVLINK_ATTR_MAX) < 0)
		return MNL_CB_OK;

	type = mnl_attr_get_type(attr);
	if (mnl_attr_validate(attr, devlink_policy[type]) < 0)
		return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	printf("%s/%s\n",
	       mnl_attr_get_str(tb[DEVLINK_ATTR_BUS_NAME]),
	       mnl_attr_get_str(tb[DEVLINK_ATTR_DEV_NAME]));

	return MNL_CB_OK;
}

static void list(struct mv88e6xxx_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_GET, flags);
	_mnlg_socket_sndrcv(ctx->nlg, nlh, list_cb, ctx);
}

static int first_device_cb(const struct nlmsghdr *nlh, void *data)
{
	struct mv88e6xxx_ctx *ctx = data;
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME])
		return MNL_CB_ERROR;

	if (!ctx->bus_name) {
		ctx->bus_name = strdup(mnl_attr_get_str(
					       tb[DEVLINK_ATTR_BUS_NAME]));
		ctx->dev_name = strdup(mnl_attr_get_str(
					       tb[DEVLINK_ATTR_DEV_NAME]));
	}

	/* TODO Check this actually is an mv88e6xxx device */

	return MNL_CB_OK;
}

static void first_device(struct mv88e6xxx_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_GET, flags);
	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, first_device_cb, ctx);
	if (err) {
		printf("Error determining first device");
		exit(EXIT_FAILURE);
	}

	if (!ctx->bus_name || !ctx->dev_name) {
		printf("No devlink devices found\n");
		exit(EXIT_FAILURE);
	}
}

static void delete_snapshot_id(struct mv88e6xxx_ctx *ctx,
			       const char *region_name, uint32_t id)
{
	struct nlmsghdr *nlh;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_DEL,
			       NLM_F_REQUEST | NLM_F_ACK);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_REGION_NAME, region_name);
	mnl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, id);

	_mnlg_socket_sndrcv(ctx->nlg, nlh, NULL, NULL);

	ctx->repeat = true;
}

static void delete_snapshot(struct mv88e6xxx_ctx *ctx, struct nlattr **tb)
{
	struct nlattr *tb_snapshot[DEVLINK_ATTR_MAX + 1] = {};
	struct nlattr *nla_sanpshot;
	const char * region_name;
	uint32_t snapshot_id;
	int err;

	region_name = mnl_attr_get_str(tb[DEVLINK_ATTR_REGION_NAME]);

	mnl_attr_for_each_nested(nla_sanpshot,
				 tb[DEVLINK_ATTR_REGION_SNAPSHOTS]) {
		err = mnl_attr_parse_nested(nla_sanpshot, attr_cb, tb_snapshot);
		if (err != MNL_CB_OK)
			return;

		if (!tb_snapshot[DEVLINK_ATTR_REGION_SNAPSHOT_ID])
			return;

		snapshot_id = mnl_attr_get_u32(
			tb_snapshot[DEVLINK_ATTR_REGION_SNAPSHOT_ID]);

		delete_snapshot_id(ctx, region_name, snapshot_id);
	}
}

static int delete_snapshots_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct mv88e6xxx_ctx *ctx = data;
	const char * region_name;
	int port;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_REGION_NAME] || !tb[DEVLINK_ATTR_REGION_SIZE])
		return MNL_CB_ERROR;

	region_name = mnl_attr_get_str(tb[DEVLINK_ATTR_REGION_NAME]);
	if (!strncmp(region_name, "port", 4)) {
		port = atoi(region_name + 4);
		if (port > ctx->ports)
			ctx->ports = port;
	}

	if (tb[DEVLINK_ATTR_REGION_SNAPSHOTS])
		delete_snapshot(ctx, tb);

	return MNL_CB_OK;
}

static void delete_snapshots(struct mv88e6xxx_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;

	/* Sending a new message while decoding an older message
	 * results in problems. So keep repeating until all regions
	 * snapshots are gone. */
	do {
		ctx->repeat = false;
		nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_GET, flags);
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
		mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);

		_mnlg_socket_sndrcv(ctx->nlg, nlh, delete_snapshots_cb, ctx);
	} while (ctx->repeat);
}

static int new_snapshot_id(struct mv88e6xxx_ctx *ctx, const char *region_name,
			   uint32_t id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_NEW,
			       NLM_F_REQUEST | NLM_F_ACK);

	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_REGION_NAME, region_name);
	mnl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, id);

	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, NULL, NULL);
	if (err)
		printf("Unable to snapshot %s\n", region_name);

	return err;
}

static int new_snapshot(struct mv88e6xxx_ctx *ctx, const char *region_name)
{
	return new_snapshot_id(ctx, region_name, SNAPSHOT_ID);
}

void dump_snapshot_add_data(struct mv88e6xxx_ctx *ctx,
			    const uint8_t *data, size_t len,
			    uint64_t addr)
{
	if (addr > MAX_SNAPSHOT_DATA) {
		printf("Data ignored, start address outside buffer\n");
		return;
	}

	if (addr + len > MAX_SNAPSHOT_DATA) {
		printf("Data truncated\n");
		len = MAX_SNAPSHOT_DATA - addr;
	}
	memcpy(ctx->snapshot_data + addr, data, len);
	ctx->data_len = addr + len;
}

static int dump_snapshot_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *nla_entry, *nla_chunk_data, *nla_chunk_addr;
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb_field[DEVLINK_ATTR_MAX + 1] = {};
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct mv88e6xxx_ctx *ctx = data;
	int err;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_REGION_CHUNKS])
		return MNL_CB_ERROR;

	mnl_attr_for_each_nested(nla_entry, tb[DEVLINK_ATTR_REGION_CHUNKS]) {
		err = mnl_attr_parse_nested(nla_entry, attr_cb, tb_field);
		if (err != MNL_CB_OK)
			return MNL_CB_ERROR;

		nla_chunk_data = tb_field[DEVLINK_ATTR_REGION_CHUNK_DATA];
		if (!nla_chunk_data)
			continue;

		nla_chunk_addr = tb_field[DEVLINK_ATTR_REGION_CHUNK_ADDR];
		if (!nla_chunk_addr)
			continue;

		dump_snapshot_add_data(ctx,
				       mnl_attr_get_payload(nla_chunk_data),
				       mnl_attr_get_payload_len(nla_chunk_data),
				       mnl_attr_get_u64(nla_chunk_addr));
	}
	return MNL_CB_OK;
}

static int dump_snapshot_id(struct mv88e6xxx_ctx *ctx, const char *region_name,
			    uint32_t id)
{
	struct nlmsghdr *nlh;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_REGION_READ,
			       NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);

	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_REGION_NAME, region_name);
	mnl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, id);

	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, dump_snapshot_cb, ctx);
	if (err)
		printf("Unable to dump snapshot %s\n", region_name);

	return err;
}

static int dump_snapshot(struct mv88e6xxx_ctx *ctx, const char *region_name)
{
	return dump_snapshot_id(ctx, region_name, SNAPSHOT_ID);
}

static int port_dump(struct mv88e6xxx_ctx *ctx, int port)
{
	char region_name[32];
	int err, reg;
	uint16_t *p;

	sprintf(region_name, "port%d", port);

	err = new_snapshot_id(ctx, region_name, SNAPSHOT_ID + port);
	if (err) {
		printf("%s: port %d err %d\n", __func__, port, err);
		return err;
	}

	err = dump_snapshot_id(ctx, region_name, SNAPSHOT_ID + port);
	if (err)
		return err;

	p = (uint16_t *)ctx->snapshot_data;
	for (reg = 0; reg < 32; reg++)
		ctx->port_regs[port][reg] = p[reg];

	return 0;
}

static const char *mv88e6161_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Reserved",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Egress rate control",
	"Egress rate control 2",
	"Port association vec",
	"Port ATU control",
	"Override",
	"Reserved",
	"Port ether type",
	"In discard low",
	"In discard high",
	"In filtered",
	"Out filtered",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Tag remap low",
	"Tag remap high",
	"Reserved",
	"Queue counters",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
};

static const char *mv88e6165_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Reserved",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Rate control",
	"Rate control 2",
	"Port association vec",
	"Port ATU control",
	"Override",
	"Policy control",
	"Port ether type",
	"In discard low",
	"In discard high",
	"In filtered",
	"Out filtered",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Tag remap low",
	"Tag remap high",
	"Reserved",
	"Queue counters",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
};

static const char *mv88e6185_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Reserved",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Rate control",
	"Rate control 2",
	"Port association vec",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"In discard low",
	"In discard high",
	"In filtered",
	"Out filtered",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Tag remap low",
	"Tag remap high",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
};

static const char *mv88e6321_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Jamming control",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Egress rate control",
	"Egress rate control 2",
	"Port association vec",
	"Port ATU control",
	"Override",
	"Policy control",
	"Port ether type",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"LED control",
	"Reserved",
	"Tag remap low",
	"Tag remap high",
	"Reserved",
	"Queue counters",
	"Reserved",
	"Reserved",
	"Debug counters",
	"Cut through control",
};

static const char *mv88e6341_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Jamming control",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Egress rate control",
	"Egress rate control 2",
	"Port association vec",
	"Port ATU control",
	"Override",
	"Policy control",
	"Port ether type",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"LED control",
	"Reserved",
	"Tag remap low",
	"Tag remap high",
	"Reserved",
	"Queue counters",
	"Queue control",
	"queue control 2",
	"Cut through control",
	"Debug counters",
};

static const char *mv88e6352_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Jamming control",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Egress rate control",
	"Egress rate control 2",
	"Port association vec",
	"Port ATU control",
	"Override",
	"Policy control",
	"Port ether type",
	"In discard low",
	"In discard high",
	"In filtered",
	"RX frame count",
	"Reserved",
	"Reserved",
	"LED control",
	"Reserved",
	"Tag remap low",
	"Tag remap high",
	"Reserved",
	"Queue counters",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
};

static const char *mv88e6390_port_reg_names[32] = {
	"Port status",
	"Physical control",
	"Flow control",
	"Switch ID",
	"Port control",
	"Port control 1",
	"Port base VLAN map",
	"Def VLAN ID & Prio",
	"Port control 2",
	"Egress rate control",
	"Egress rate control 2",
	"Port association vec",
	"Port ATU control",
	"Override",
	"Policy control",
	"Port ether type",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"LED control",
	"IP prio map table",
	"IEEE prio map table",
	"Port control 3",
	"Reserved",
	"Queue counters",
	"Queue control",
	"Reserved",
	"Cut through control",
	"Debug counters",
};

static void ports_print(struct mv88e6xxx_ctx *ctx)
{
	int port, reg;

	printf("			");
	for (port = 0; port <= ctx->ports; port++)
		printf("%4d ", port);
	putchar('\n');

	for (reg = 0; reg < 32; reg++) {
		printf("%02x ", reg);

		switch (ctx->chip) {
		case MV88E6190:
		case MV88E6191:
		case MV88E6290:
		case MV88E6390:
			printf("%22s ", mv88e6390_port_reg_names[reg]);
			break;
		case MV88E6171:
		case MV88E6175:
		case MV88E6350:
		case MV88E6351:
		case MV88E6172:
		case MV88E6176:
		case MV88E6240:
		case MV88E6352:
			printf("%22s ", mv88e6352_port_reg_names[reg]);
			break;
		case MV88E6131:
		case MV88E6185:
			printf("%22s ", mv88e6185_port_reg_names[reg]);
			break;
		case MV88E6320:
		case MV88E6321:
			printf("%22s ", mv88e6321_port_reg_names[reg]);
			break;
		case MV88E6341:
		case MV88E6141:
			printf("%22s ", mv88e6341_port_reg_names[reg]);
			break;
		case MV88E6165:
			printf("%22s ", mv88e6165_port_reg_names[reg]);
			break;
		case MV88E6123:
		case MV88E6161:
			printf("%22s ", mv88e6161_port_reg_names[reg]);
			break;
		}

		for (port = 0; port <= ctx->ports; port++)
			printf("%04x ", ctx->port_regs[port][reg]);
		putchar('\n');
	}
}

static void cmd_ports(struct mv88e6xxx_ctx *ctx)
{
	int port;
	int err;

	for (port = 0; port <= ctx->ports; port++) {
		err = port_dump(ctx, port);
		if (err)
			break;
	}
	ports_print(ctx);
}

static char *binary(char *buffer, int val, int bits)
{
	int i;

	for (i = 0; i < bits; i++)
		buffer[i] = (val & (1 << i) ? '1' : '0');
	buffer[i] = 0;

	return buffer;
}

static const char *const mv88e6xxx_unicaststates[] = {
	"Unused",
	"Age 1",
	"Age 2",
	"Age 3",
	"Age 4",
	"Age 5",
	"Age 6",
	"Age 7",
	"Static policy",
	"Static policy with priority override",
	"Static non rate limited",
	"Static non rate limited with priority override",
	"Static frames with DA as MGMT",
	"Static frames with DA as MGMT with priority override",
	"Static",
	"Static with priority override"
};

static const char *mv88e6xxx_unicaststate2str(uint8_t state)
{
	if (state < ARRAY_SIZE(mv88e6xxx_unicaststates))
		return mv88e6xxx_unicaststates[state];
	printf("Invalid state %d\n", state);
	exit(EXIT_FAILURE);
}

static const char *const mv88e6xxx_multicaststates[] = {
	"Unused",
	"Reserved",
	"Reserved",
	"Reserved",
	"Static policy",
	"Static non rate limited",
	"Static frames with DA as MGMT",
	"Static",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Static policy with priority override"
	"Static non rate limited with priority override",
	"Static frames with DA as MGMT with priority override",
	"Static with priority override"
};

static const char *mv88e6xxx_multicaststate2str(uint8_t state)
{
	if (state < ARRAY_SIZE(mv88e6xxx_multicaststates))
		return mv88e6xxx_multicaststates[state];
	printf("Invalid state %d\n", state);
	exit(EXIT_FAILURE);
}

static char ports_labels[]="0123456789ABCDEF";

static void atu_mv88e6xxx(struct mv88e6xxx_ctx *ctx, uint16_t portvec_mask,
			  int portvec_bits)
{
	struct mv88e6xxx_devlink_atu_entry *table;
	char buffer[16];
	bool trunk, multicast;
	uint8_t state, prio;
	uint16_t portvec;
	int entries, i;

	table = (struct mv88e6xxx_devlink_atu_entry *)ctx->snapshot_data;
	entries = ctx->data_len / sizeof(struct mv88e6xxx_devlink_atu_entry);

	printf("FID  MAC	       T ");
	for (i = 0; i < portvec_bits; i++)
		putchar(ports_labels[i]);
	printf(" Prio State\n");

	for (i = 0; i < entries; i++) {
		state = table[i].atu_data & 0xf;
		trunk = !!(table[i].atu_data & 0x8000);
		portvec = (table[i].atu_data & portvec_mask) >> 4;

		if (!state)
			continue;

		multicast = !!(table[i].atu_01 & 0x0100);
		prio = (table[i].atu_op & 0x0700) >> 8;

		printf("%4d %02x:%02x:%02x:%02x:%02x:%02x %1s ",
		       table[i].fid,
		       (table[i].atu_01 & 0xff00) >> 8,
		       (table[i].atu_01 & 0x00ff) >> 0,
		       (table[i].atu_23 & 0xff00) >> 8,
		       (table[i].atu_23 & 0x00ff) >> 0,
		       (table[i].atu_45 & 0xff00) >> 8,
		       (table[i].atu_45 & 0x00ff) >> 0,
		       (trunk ? "T" : ""));

		if (trunk)
			printf("%11d ", portvec & 0xf);
		else
			printf("%11s ", binary(buffer, portvec, 11));

		printf("%4d %s\n",
		       prio,
		       (multicast ? mv88e6xxx_multicaststate2str(state) :
			mv88e6xxx_unicaststate2str(state)));
	}
}

static void cmd_atu(struct mv88e6xxx_ctx *ctx)
{
	int err;

	printf("ATU:\n");

	err = new_snapshot(ctx, "atu");
	if (err)
		return;

	err = dump_snapshot(ctx, "atu");
	if (err)
		return;

	switch (ctx->chip) {
	case MV88E6190:
	case MV88E6191:
	case MV88E6290:
	case MV88E6390:
		return atu_mv88e6xxx(ctx, 0x3ff, 11);
	case MV88E6171:
	case MV88E6175:
	case MV88E6350:
	case MV88E6351:
	case MV88E6172:
	case MV88E6176:
	case MV88E6240:
	case MV88E6352:
		return atu_mv88e6xxx(ctx, 0x07f, 7);
	case MV88E6141:
	case MV88E6341:
		return atu_mv88e6xxx(ctx, 0x03f, 6);
	case MV88E6320:
	case MV88E6321:
		return atu_mv88e6xxx(ctx, 0x07f, 7);
	case MV88E6220:
	case MV88E6250:
		return atu_mv88e6xxx(ctx, 0x03f, 7);
	case MV88E6131:
	case MV88E6185:
		return atu_mv88e6xxx(ctx, 0x0ff, 8);
	case MV88E6123:
	case MV88E6161:
	case MV88E6165:
		return atu_mv88e6xxx(ctx, 0x03f, 6);
	default:
		printf("Unknown mv88e6xxx chip %x\n", ctx->chip);
	}
	return;
}

static void cmd_vtu(struct mv88e6xxx_ctx *ctx)
{
	int err;

	printf("VTU:\n");

	err = new_snapshot(ctx, "vtu");
	if (err)
		return;

	err = dump_snapshot(ctx, "vtu1");
	if (err)
		return;
}

static void cmd_global1(struct mv88e6xxx_ctx *ctx)
{
	uint16_t *g2;
	int err;
	int i;

	printf("Global1:\n");

	err = new_snapshot(ctx, "global1");
	if (err)
		return;

	err = dump_snapshot(ctx, "global1");
	if (err)
		return;

	if (ctx->data_len != 64) {
		printf("Unexpected data length. %ld != 64\n", ctx->data_len);
		return;
	}

	g2 = (uint16_t *)ctx->snapshot_data;
	for (i = 0; i < 32; i++)
		printf("%2d %04x\n", i, g2[i]);
}

static void cmd_global2(struct mv88e6xxx_ctx *ctx)
{
	uint16_t *g2;
	int err;
	int i;

	printf("Global2:\n");

	err = new_snapshot(ctx, "global2");
	if (err)
		return;

	err = dump_snapshot(ctx, "global2");
	if (err)
		return;

	if (ctx->data_len != 64) {
		printf("Unexpected data length. %ld != 64\n", ctx->data_len);
		return;
	}

	g2 = (uint16_t *)ctx->snapshot_data;
	for (i = 0; i < 32; i++)
		printf("%2d %04x\n", i, g2[i]);
}

static int get_info_cb(const struct nlmsghdr *nlh, void *data)
{
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
	struct mv88e6xxx_ctx *ctx = data;
	const char *driver_name;
	struct nlattr *version;
	int ret;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);

	if (!tb[DEVLINK_ATTR_BUS_NAME] || !tb[DEVLINK_ATTR_DEV_NAME] ||
	    !tb[DEVLINK_ATTR_INFO_DRIVER_NAME] ||
	    !tb[DEVLINK_ATTR_INFO_VERSION_FIXED])
		return MNL_CB_ERROR;

	driver_name = mnl_attr_get_str(tb[DEVLINK_ATTR_INFO_DRIVER_NAME]);
	if (strcmp(driver_name, "mv88e6xxx")) {
		printf("%s/%s is not an mv88e6xxx\n", ctx->bus_name,
			ctx->dev_name);
		exit(EXIT_FAILURE);
	}

	mnl_attr_for_each(version, nlh, sizeof(struct genlmsghdr)) {
		struct nlattr *tb[DEVLINK_ATTR_MAX + 1] = {};
		const char *ver_value;
		const char *ver_name;
		int err;

		if (mnl_attr_get_type(version) !=
		    DEVLINK_ATTR_INFO_VERSION_FIXED)
			continue;

		err = mnl_attr_parse_nested(version, attr_cb, tb);
		if (err != MNL_CB_OK)
			continue;

		if (!tb[DEVLINK_ATTR_INFO_VERSION_NAME] ||
		    !tb[DEVLINK_ATTR_INFO_VERSION_VALUE])
			continue;

		ver_name = mnl_attr_get_str(tb[DEVLINK_ATTR_INFO_VERSION_NAME]);
		ver_value = mnl_attr_get_str(tb[DEVLINK_ATTR_INFO_VERSION_VALUE]);

		if (strcmp(ver_name, "asic.id"))
			continue;

		ret = sscanf(ver_value, "Marvell 88E%ud", &ctx->chip);
		if (ret != 1) {
			printf("Unable to parse ASIC version %s\n",
			       ver_value);
			exit(EXIT_FAILURE);
		}
		return MNL_CB_OK;
	}
	return MNL_CB_OK;
}

static void get_info(struct mv88e6xxx_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	int err;

	nlh = mnlg_msg_prepare(ctx->nlg, DEVLINK_CMD_INFO_GET, flags);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_BUS_NAME, ctx->bus_name);
	mnl_attr_put_strz(nlh, DEVLINK_ATTR_DEV_NAME, ctx->dev_name);

	err = _mnlg_socket_sndrcv(ctx->nlg, nlh, get_info_cb, ctx);
	if (err) {
		printf("Unable to get devices info\n");
		exit(EXIT_FAILURE);
	}
}

static unsigned int strslashcount(char *str)
{
	unsigned int count = 0;
	char *pos = str;

	while ((pos = strchr(pos, '/'))) {
		count++;
		pos++;
	}
	return count;
}

static int strslashrsplit(char *str, const char **before, const char **after)
{
	char *slash;

	slash = strrchr(str, '/');
	if (!slash)
		return -EINVAL;
	*slash = '\0';
	*before = str;
	*after = slash + 1;
	return 0;
}

int main(int argc, char * argv[])
{
	struct mv88e6xxx_ctx ctx = {0};
	bool do_atu = false;
	bool do_vtu = false;
	bool do_global1 = false;
	bool do_global2 = false;
	bool do_ports = false;
	bool do_list = false;
	bool have_device = false;
	bool debug = false;

	static struct option long_options[] = {
		{"atu",	    no_argument,       0,  0 },
		{"vtu",	    no_argument,       0,  0 },
		{"global1", no_argument,       0,  0 },
		{"global2", no_argument,       0,  0 },
		{"ports",   no_argument,       0,  0 },
		{"device",  required_argument, 0, 'd'},
		{"list",    no_argument,       0, 'l'},
		{"debug",   no_argument,       0, 'D'},
		{"help",    no_argument,       0, 'h'},
		{0,	    0,		       0,  0 }
	};

	while (1) {
		int option_index = 0;
		int c;

		c = getopt_long(argc, argv, "d:lDh",
				long_options, &option_index);
		if (c == -1)
			break;

		switch(c) {
		case 0:
			switch (option_index) {
			case 0:
				do_atu = true;
				break;
			case 1:
				do_vtu = true;
				break;
			case 2:
				do_global1 = true;
				break;
			case 3:
				do_global2 = true;
				break;
			case 4:
				do_ports = true;
				break;
			}
			break;
		case 'd':
			if (strslashcount(optarg) != 1) {
				printf("Wrong devlink identification string format.\n");
				printf("Expected \"bus_name/dev_name\".\n");
				exit(EXIT_FAILURE);
			}
			strslashrsplit(optarg, &ctx.bus_name, &ctx.dev_name);
			have_device = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_FAILURE);
		case 'l':
			do_list = true;
			break;
		case 'D':
			debug = true;
			break;
		default:
			printf("?? getopt returned character code %d ??\n", c);
			exit(EXIT_FAILURE);
		}
	}

	ctx.nlg = mnlg_socket_open(DEVLINK_GENL_NAME, DEVLINK_GENL_VERSION,
				   debug);
	if (!ctx.nlg) {
		printf("Failed to connect to devlink Netlink\n");
		exit(EXIT_FAILURE);
	}

	if (do_list) {
		list(&ctx);
		exit(EXIT_SUCCESS);
	}

	if (!have_device) {
		first_device(&ctx);
		printf("Using device <%s/%s>\n", ctx.bus_name, ctx.dev_name);
	}

	get_info(&ctx);

	delete_snapshots(&ctx);

	if (do_ports) {
		cmd_ports(&ctx);
		delete_snapshots(&ctx);
	}

	if (do_atu) {
		cmd_atu(&ctx);
		delete_snapshots(&ctx);
	}

	if (do_vtu) {
		cmd_vtu(&ctx);
		delete_snapshots(&ctx);
	}

	if (do_global1) {
		cmd_global1(&ctx);
		delete_snapshots(&ctx);
	}

	if (do_global2) {
		cmd_global2(&ctx);
		delete_snapshots(&ctx);
	}

	mnlg_socket_close(ctx.nlg);
}
