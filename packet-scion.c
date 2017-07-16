#include "config.h"

#include <epan/packet.h>

#define SCION_PORT 30096

static int proto_scion = -1;

#define SCION_VERSION_FLAG 0xF000
#define SCION_DST_TYPE_FLAG 0x0FC0
#define SCION_SRC_TYPE_FLAG 0x003F

static int hf_scion_version = -1;
static int hf_scion_dst_type = -1;
static int hf_scion_src_type = -1;
static int hf_scion_begin_flags = -1;
static int hf_scion_total_len = -1;
static int hf_scion_hdr_len = -1;
static int hf_scion_curr_inf = -1;
static int hf_scion_curr_hf = -1;
static int hf_scion_next_hdr = -1;

static int hf_scion_dst_isd_as = -1;
static int hf_scion_dst_isd = -1;
static int hf_scion_dst_as = -1;
static int hf_scion_src_isd_as = -1;
static int hf_scion_src_isd = -1;
static int hf_scion_src_as = -1;

static int hf_scion_dst_addr_ipv4 = -1;
static int hf_scion_dst_addr_ipv6 = -1;
static int hf_scion_dst_addr_svc = -1;
static int hf_scion_src_addr_ipv4 = -1;
static int hf_scion_src_addr_ipv6 = -1;
static int hf_scion_src_addr_svc = -1;
static int hf_scion_addr_padding = -1;

static int ett_scion_begin_flags = -1;
static int ett_scion_dst_isd_as = -1;
static int ett_scion_src_isd_as = -1;
static gint ett_scion = -1;

static const value_string addr_type_names[] = {
	{ 0, "None" },
	{ 1, "IPv4" },
	{ 2, "IPv6" },
	{ 3, "Service" },
};

void proto_register_scion(void) {
	static hf_register_info hf[] = {
		{ &hf_scion_begin_flags,
			{"Start of packet", "scion.flags",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_version,
			{ "SCION Version", "scion.version",
			FT_UINT16, BASE_DEC,
			NULL, SCION_VERSION_FLAG,
			NULL, HFILL }
		}, 
		{ &hf_scion_dst_type,
			{ "Destination address type", "scion.dst.type",
			FT_UINT16, BASE_HEX,
			VALS(addr_type_names), SCION_DST_TYPE_FLAG,
			NULL, HFILL }
		},
		{ &hf_scion_src_type,
			{ "Source address type", "scion.src.type",
			FT_UINT16, BASE_HEX,
			VALS(addr_type_names), SCION_SRC_TYPE_FLAG,
			NULL, HFILL }
		},
		{ &hf_scion_total_len,
			{ "Total length", "scion.length",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_hdr_len,
			{ "Header length", "scion.hdr.length",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_curr_inf,
			{ "Current info field", "scion.currinf",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_curr_hf,
			{ "Current header field", "scion.currhf",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_next_hdr,
			{ "Next header type", "scion.nexthdr",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_dst_isd_as,
			{ "Destination ISD-AS", "scion.dst.isdas",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_scion_dst_isd,
			{ "Destination ISD", "scion.dst.isd",
			FT_UINT32, BASE_DEC,
			NULL, 0xFFF00000,
			NULL, HFILL }
		},
		{ &hf_scion_dst_as,
			{ "Destination AS", "scion.dst.as",
			FT_UINT32, BASE_DEC,
			NULL, 0x000FFFFF,
			NULL, HFILL }
		},
		{ &hf_scion_src_isd_as,
			{ "Source ISD-AS", "scion.src.isdas",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_scion_src_isd,
			{ "Source ISD", "scion.src.isd",
			FT_UINT32, BASE_DEC,
			NULL, 0xFFF00000,
			NULL, HFILL }
		},
		{ &hf_scion_src_as,
			{ "Destination AS", "scion.src.as",
			FT_UINT32, BASE_DEC,
			NULL, 0x000FFFFF,
			NULL, HFILL }
		},
		{ &hf_scion_dst_addr_ipv4,
			{ "Destination address", "scion.dst.addr",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_dst_addr_ipv6,
			{ "Destination address", "scion.dst.addr",
			FT_IPv6, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_dst_addr_svc,
			{ "Destination address", "scion.dst.addr",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_src_addr_ipv4,
			{ "Source address", "scion.src.addr",
			FT_IPv4, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_src_addr_ipv6,
			{ "Source address", "scion.src.addr",
			FT_IPv6, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_src_addr_svc,
			{ "Source address", "scion.src.addr",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_scion_addr_padding,
			{ "Address padding bytes", "scion.addr.padding",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_scion,
		&ett_scion_begin_flags,
		&ett_scion_dst_isd_as,
		&ett_scion_src_isd_as,
	};

	proto_scion = proto_register_protocol (
		"SCION Protocol",
		"SCION",
		"scion"
		);

	proto_register_field_array(proto_scion, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

static int dissect_scion(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

void proto_reg_handoff_scion(void) {
	static dissector_handle_t scion_handle;

	scion_handle = create_dissector_handle(dissect_scion, proto_scion);
	dissector_add_uint("udp.port", SCION_PORT, scion_handle);
}

/*
static int dissect_if(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {

}

static int dissect_hf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {

}
*/

static int dissect_scion(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	gint offset = 0;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCION");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	static const int * flags [] = {
		&hf_scion_version,
		&hf_scion_dst_type,
		&hf_scion_src_type,
		NULL
	};

	proto_item *ti = proto_tree_add_item(tree, proto_scion, tvb, 0, -1, ENC_NA);
	proto_tree *scion_tree = proto_item_add_subtree(ti, ett_scion);
	proto_tree_add_bitmask(scion_tree, tvb, offset, hf_scion_begin_flags, ett_scion_begin_flags, flags, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(scion_tree, hf_scion_total_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(scion_tree, hf_scion_hdr_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(scion_tree, hf_scion_curr_inf, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(scion_tree, hf_scion_curr_hf, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(scion_tree, hf_scion_next_hdr, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	static const int * dst_isd_as [] = {
		&hf_scion_dst_isd,
		&hf_scion_dst_as,
		NULL
	};
	proto_tree_add_bitmask(scion_tree, tvb, offset, hf_scion_dst_isd_as, ett_scion_dst_isd_as, dst_isd_as, ENC_BIG_ENDIAN);
	offset += 4;

	static const int * src_isd_as [] = {
		&hf_scion_src_isd,
		&hf_scion_src_as,
		NULL
	};
	proto_tree_add_bitmask(scion_tree, tvb, offset, hf_scion_src_isd_as, ett_scion_src_isd_as, src_isd_as, ENC_BIG_ENDIAN);
	offset += 4;

	guint8 address_length = 0;
	guint8 dst_type = ((tvb_get_guint8(tvb, 0) & 0x0F)<<2) + (tvb_get_guint8(tvb, 1) >> 6);
	if (dst_type == 0x01) {
		proto_tree_add_item(scion_tree, hf_scion_dst_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		address_length += 4;
	} else if (dst_type == 0x02) {
		proto_tree_add_item(scion_tree, hf_scion_dst_addr_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
		address_length += 16;
	} else if (dst_type == 0x03) {
		proto_tree_add_item(scion_tree, hf_scion_dst_addr_svc, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		address_length += 2;
	}

	guint8 src_type = tvb_get_guint8(tvb, 1) & 0x3F;
	if (src_type == 0x01) {
		proto_tree_add_item(scion_tree, hf_scion_src_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		address_length += 4;
	} else if (src_type == 0x02) {
		proto_tree_add_item(scion_tree, hf_scion_src_addr_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
		offset += 16;
		address_length += 16;
	} else if (src_type == 0x03) {
		proto_tree_add_item(scion_tree, hf_scion_src_addr_svc, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		address_length += 2;
	}

	guint8 padding = (32 - address_length) % 8;
	proto_tree_add_item(scion_tree, hf_scion_addr_padding, tvb, offset, padding, ENC_BIG_ENDIAN);
	offset += padding;


	return tvb_captured_length(tvb);
}
