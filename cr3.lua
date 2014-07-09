--
-- tmanning
--

cr3_proto = Proto("cr3","Crimson v3")

-- define the field names, widths, descriptions, and number base
-- looks like lua structs is what I should use here
local pf_zero = ProtoField.uint8("cr3.zero", "Zero", base.HEX)
local pf_payload_length = ProtoField.uint8("cr3.len", "Length", base.HEX)
local pf_reg = ProtoField.uint8("cr3.reg", "Register number", base.HEX)
local pf_payload = ProtoField.bytes("cr2.payload", "Payload")

-- example I followed said not to do the fields like this, risk of missing some
cr3_proto.fields = {
	pf_zero,
	pf_payload_length,
	pf_reg,
	pf_payload
}

function cr3_proto.dissector(tvbuf,pinfo,tree)
	-- set the protocol column based on the Proto object
	pinfo.cols.protocol = cr3_proto.description

	-- length of the entire CR3 payload
	local pktlen = tvbuf:reported_length_remaining()

	-- define this entire length as the object of dissection
	local subtree = tree:add(cr3_proto, tvbuf:range(0, pktlen))

	-- setup fields in the proper order and width
	subtree:add(pf_zero,tvbuf(0,1))
	subtree:add(pf_payload_length,tvbuf(1,1))
	subtree:add(pf_reg, tvbuf(2,2))

	-- payload gets broken out
	-- this pattern feels buggy
	local payloadtree = subtree:add("Payload", tvbuf:range(4, pktlen - 4))
	payloadtree:add(pf_payload, tvbuf(4)):append_text(string.format(" (0x%02x bytes)", tvbuf:reported_length_remaining() - 4))

	

end
-- load the udp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle udp port 7777
tcp_table:add(789,cr3_proto)
