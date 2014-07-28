--
-- lol
--

cr3_proto = Proto("cr3","Crimson v3")

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
	pzero,
	prest,
	pstring
}

-- trying out a global variable for processing any cr3 segments
local processing_segment = false
local reassembled_length = 0
local segment_cur = 0 

function cr3_proto.dissector(tvbuf,pinfo,tree)
	print("Processing fragment flag ", processing_segment)
	-- set the protocol column based on the Proto object
	pinfo.cols.protocol = cr3_proto.description

	-- length of the entire CR3 payload
	local pktlen = tvbuf:reported_length_remaining()

	-- define this entire length as the object of dissection
	local subtree = tree:add(cr3_proto, tvbuf:range(0, pktlen))
	
	-- setup fields in the proper order and width
	local offset = 0
	
	local cr3len = tvbuf(offset,2):uint()
	subtree:add(pf_payload_length,tvbuf(offset,2))
	offset = offset + 2
	
	local reg = tvbuf(offset,2):uint()
	subtree:add(pf_reg, reg)
	offset = offset + 2

	-- payload gets broken out
	-- this pattern feels buggy
	local payloadtree = subtree:add(pf_payload, tvbuf:range(offset, pktlen - offset))
	payloadtree:append_text(string.format(" (0x%02x bytes)", tvbuf:reported_length_remaining() - 4))

	payloadtree:add(ptype, tvbuf(offset, 2))
	local packettype = tvbuf:range(offset, 2):uint()
	offset = offset + 2
	
	-- every place a packettype is checked, check to make sure ! processing_segment
	-- other wise a bug may happen with the processing of messages 
	-- // Sun Jul 27 14:19:41 CDT 2014 - ++TODO: LOOK FOR THIS BUG IN THE HANDLING OF SEGMENTS
	if not processing_segment and (packettype == 0x0300 and ( reg == 0x012a or reg == 0x012b)) then
		string = tvbuf:range(offset):stringz()
		payloadtree:add(pstring, string)
	end
	
	-- handle CR3 segmentation
	-- packettype 0x1500 sets the flag
	-- 
	if packettype == 0x1500 then -- and (pktlen - cr3len > 2) then 
		processing_segment = true
		segment_cur = pinfo.desegment_offset or 0
		
		reassembled_length = tvbuf:range(offset+ 4, 2):uint()
		print(string.format("reassembled length 0x%04x", reassembled_length))
		pinfo.desegment_offset = 0 
		pinfo.desegment_len = reassembled_length
		return
	elseif processing_segment and segment_cur < then
		segment_cur = segment_cur + cr3len
		pinfo.desegment_offset = pinfo.desegment_offset + cr3len
		print(string.format("Processing segment: pinfo.desegment_offset 0x%04x", pinfo.desegment_offset))

		return
	elseif
			
	end

	-- if offset < pktlen then 
	-- 	payloadtree:add(prest, tvbuf:range(offset, pktlen-offset))
	-- 	offset = offset + 2
	-- end

	-- setting CR3 summary data into the info column in the UI
	pinfo.cols.info = string.format("Register: 0x%04x, Type: 0x%04x", reg, packettype)

	-- debug
	print(string.format("Register: 0x%04x, Type: 0x%04x", reg, packettype))
	print(string.format("pktlen 0x%04x, cr3.length 0x%04x", pktlen, cr3len))

	print("\n")
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol tcp:789
tcp_table:add(789,cr3_proto)
print("Wireshark version = ", get_version())
