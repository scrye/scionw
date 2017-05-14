#include "config.h"

#include <epan/packet.h>

#define SCION_PORT 30096

static int proto_scion = -1;

void proto_register_scion(void) {
	proto_scion = proto_register_protocol (
		"SCION Protocol",
		"SCION",
		"scion"
		);
}

static int dissect_scion(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

void proto_reg_handoff_scion(void) {
	static dissector_handle_t scion_handle;

	scion_handle = create_dissector_handle(dissect_scion, proto_scion);
	dissector_add_uint("udp.port", SCION_PORT, scion_handle);
}

static int dissect_scion(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SCION");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	return tvb_captured_length(tvb);
}
