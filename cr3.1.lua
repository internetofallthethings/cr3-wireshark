--
-- lol
--

cr3_proto = Proto("cr3.1","Crimson v3 dev 1")

-- define the field names, widths, descriptions, and number base
-- looks like lua structs is what I should use here
local pf_payload_length = ProtoField.uint16("cr3.len", "Length", base.HEX)
local pf_reg = ProtoField.uint16("cr3.reg", "Register number", base.HEX)
local pf_payload = ProtoField.bytes("cr3.payload", "Payload")
local ptype = ProtoField.uint16("cr3.payload.type", "Type", base.HEX)
local pzero = ProtoField.uint16("cr3.payload.zero", "Zero", base.HEX)

local prest = ProtoField.bytes("cr3.payload.rest", "Data")
local pstring = ProtoField.string("cr3.payload.string", "String")

-- example I followed said not to do the fields like this, risk of missing some
cr3_proto.fields = {
	pf_payload_length,
	pf_reg,
	pf_payload,
	ptype,
	pstring
}

-- trying out a global variable for processing any cr3 segments
local processing_segment = false
local reassembled_length = 0
local segment_cur = 0 
local segment_data = nil

function debug_print(arg)
	print(arg)
end

function cr3_proto.dissector(tvbuf,pinfo,tree)
	debug_print(string.format("cr3_proto.dissector processing_segment = %s -------------------------------------------------------", processing_segment))

	-- length of the entire packet
	local pktlen = tvbuf:reported_length_remaining()

	-- pf_payload_length
	local cr3len = tvbuf(0,2):uint()
		
	debug_print(string.format("pktlen=0x%02x", pktlen))
	debug_print(string.format("cr3len=0x%02x", cr3len))

	if not processing_segment then
		if pktlen == cr3len + 2 then
			dissect_cr3(tvbuf, pinfo, tree, cr3len)
			return
		elseif cr3len > pktlen then
			processing_segment = true
			-- pinfo.can_desegment = 1
			pinfo.desegment_len = cr3len - pktlen

		else
			debug_print("HUH?")
			debug_print(string.format("cr3len=0x%02x", cr3len))
			debug_print(string.format("pktlen=0x%02x", pktlen))
			dissect_cr3(tvbuf, pinfo, tree, cr3len)
			print "JUST CALLED DISSECT_CR3"
			return
		end
	else
		debug_print("PROCESSING_SEGMENT")
		dissect_cr3(tvbuf, pinfo, tree, cr3len)
		processing_segment = false
		return
	end
		
end

function dissect_cr3(tvbuf,pinfo,tree,cr3len)
	debug_print("dissect_cr3")

	-- set the protocol column based on the Proto object
	pinfo.cols.protocol = cr3_proto.description
	debug_print("line 70")
	
	-- length of the entire CR3 payload
	local pktlen = tvbuf:reported_length_remaining()
	debug_print(string.format("line 74: pktlen=0x%02x, cr3len=0x%02x", pktlen, cr3len))
	
	-- define this entire length as the object of dissection
	local subtree = tree:add(cr3_proto, tvbuf:range(0, pktlen))
	debug_print("line 78")
		
	-- setup fields in the proper order and width
	local offset = 0
		
	local cr3len = tvbuf(offset,2):uint()
	subtree:add(pf_payload_length,tvbuf(offset,2))
	offset = offset + 2
	debug_print("86")
		
	local reg = tvbuf(offset,2):uint()
	subtree:add(pf_reg, reg)
	offset = offset + 2
	debug_print("91")
	
	-- payload gets broken out
	-- this pattern feels buggy
	local payloadtree = subtree:add(pf_payload, tvbuf:range(offset, pktlen - offset))
	payloadtree:append_text(string.format(" (0x%02x bytes)", tvbuf:reported_length_remaining() - 4))
	debug_print("97")
	
	payloadtree:add(ptype, tvbuf(offset, 2))
	local packettype = tvbuf:range(offset, 2):uint()
	offset = offset + 2
	debug_print("102")
	
	debug_print(string.format("pktlen 0x%04x, cr3len 0x%04x, reg 0x%04x", pktlen, cr3len, reg))
		
	-- every place a packettype is checked, check to make sure ! processing_segment
	-- other wise a bug may happen with the processing of messages 
	-- // Sun Jul 27 14:19:41 CDT 2014 - ++TODO: LOOK FOR THIS BUG IN THE HANDLING OF SEGMENTS
	if (packettype == 0x0300 and ( reg == 0x012a or reg == 0x012b)) then
		debug_print("Trying loop 110")
		string = tvbuf:range(offset):stringz()
		payloadtree:add(pstring, string)
	end
	debug_print("113")

	debug_print "After segment processing code"

	-- setting CR3 summary data into the info column in the UI
	pinfo.cols.info = string.format("Register: 0x%04x, Type: 0x%04x", reg, packettype)

	debug_print("\n")

	return
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol tcp:789
tcp_table:add(789,cr3_proto)
print("Wireshark version = ", get_version())
