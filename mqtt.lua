--
-- mqtt.lua is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Lesser General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- mqtt.lua is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with mqtt.lua.  If not, see <http://www.gnu.org/licenses/>.
--
--
-- Copyright 2012 Vicente Ruiz Rodríguez <vruiz2.0@gmail.com>. All rights reserved.
--

do
	-- Create a new dissector
	MQTTPROTO = Proto("MQTT", "MQ Telemetry Transport")
	local bitw = require("bit")
	local f = MQTTPROTO.fields
	-- Fix header: byte 1
	f.message_type = ProtoField.uint8("mqtt.message_type", "Message Type", base.HEX, nil, 0xF0)
	f.dup = ProtoField.uint8("mqtt.dup", "DUP Flag", base.DEC, nil, 0x08)
	f.qos = ProtoField.uint8("mqtt.qos", "QoS Level", base.DEC, nil, 0x06)
	f.retain = ProtoField.uint8("mqtt.retain", "Retain", base.DEC, nil, 0x01)
	-- Fix header: byte 2
	f.remain_length = ProtoField.uint8("mqtt.remain_length", "Remain Length")

	-- Connect
	f.connect_protocol_name = ProtoField.string("mqtt.connect.protocol_name", "Protocol Name")
	f.connect_protocol_version = ProtoField.uint8("mqtt.connect.protocol_version", "Protocol Version")
	f.connect_username = ProtoField.uint8("mqtt.connect.username", "Username Flag", base.DEC, nil, 0x80)
	f.connect_password = ProtoField.uint8("mqtt.connect.password", "Password Flag", base.DEC, nil, 0x40)
	f.connect_will_retain = ProtoField.uint8("mqtt.connect.will_retain", "Will Retain Flag", base.DEC, nil, 0x20)
	f.connect_will_qos = ProtoField.uint8("mqtt.connect.will_qos", "Will QoS Flag", base.DEC, nil, 0x18)
	f.connect_will = ProtoField.uint8("mqtt.connect.will", "Will Flag", base.DEC, nil, 0x04)
	f.connect_clean_session = ProtoField.uint8("mqtt.connect.clean_session", "Clean Session Flag", base.DEC, nil, 0x02)
	f.connect_keep_alive = ProtoField.uint16("mqtt.connect.keep_alive", "Keep Alive (secs)")
	f.connect_payload_clientid = ProtoField.string("mqtt.connect.payload.clientid", "Client ID")
	f.connect_payload_username = ProtoField.string("mqtt.connect.payload.username", "Username")
	f.connect_payload_password = ProtoField.string("mqtt.connect.payload.password", "Password")
	
	-- Connack
	f.connack_code = ProtoField.string("mqtt.connack.return_code", "Return Code")
	f.connack_reason = ProtoField.string("mqtt.connack.return_reason", "Reason Phrase")

	-- Publish
	f.publish_topic = ProtoField.string("mqtt.publish.topic", "Topic")
	f.publish_message_id = ProtoField.uint16("mqtt.publish.message_id", "Message ID")
	f.publish_data = ProtoField.string("mqtt.publish.data", "Data")

	-- Subscribe
	f.subscribe_message_id = ProtoField.uint16("mqtt.subscribe.message_id", "Message ID")
	f.subscribe_topic = ProtoField.string("mqtt.subscribe.topic", "Topic")
	f.subscribe_qos = ProtoField.uint8("mqtt.subscribe.qos", "QoS")

	-- SubAck
	f.suback_qos = ProtoField.uint8("mqtt.suback.qos", "QoS")

	-- Suback
	f.suback_message_id = ProtoField.uint16("mqtt.suback.message_id", "Message ID")
	f.suback_qos = ProtoField.uint8("mqtt.suback.qos", "QoS")
	--
	f.payload_data = ProtoField.bytes("mqtt.payload", "Payload Data")

	-- decoding of fixed header remaining length
	-- according to MQTT V3.1
	function lengthDecode(buffer, offset)
		local multiplier = 1
		local value = 0
		local digit = 0
		repeat
			 digit = buffer(offset, 1):uint()
			 offset = offset + 1
			 value = value + bitw.band(digit,127) * multiplier
			 multiplier = multiplier * 128
		until (bitw.band(digit,128) == 0)
		return offset, value
	end -- lengthDecode
	
	local msg_types = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 }
  msg_types[1] = "CONNECT"
  msg_types[2] = "CONNACK"
  msg_types[3] = "PUBLISH"
  msg_types[4] = "PUBACK"
  msg_types[5] = "PUBREC"
  msg_types[6] = "PUBREL"
  msg_types[7] = "PUBCOMP"
  msg_types[8] = "SUBSCRIBE"
  msg_types[9] = "SUBACK"
  msg_types[10] = "UNSUBSCRIBE"
  msg_types[11] = "UNSUBACK"
  msg_types[12] = "PINGREQ"
  msg_types[13] = "PINGRESP"
  msg_types[14] = "DISCONNECT"
    
  local connack_return_reasons = { 0, 1, 2, 3, 4, 5 }
  connack_return_reasons[0] = "Connection Accepted"
  connack_return_reasons[1] = "Connection Refused: unacceptable protocol version"
  connack_return_reasons[2] = "Connection Refused: identifier rejected"
  connack_return_reasons[3] = "Connection Refused: server unavailable"
  connack_return_reasons[4] = "Connection Refused: bad user name or password"
  connack_return_reasons[5] = "Connection Refused: not authorized"
  for i=6, 256 do
    connack_return_reasons[i] = "Reserved for future use"
  end
	
	function dissect_mqtt_pdus(buffer, pinfo, tree)
	    local offset = pinfo.desegment_offset or 0
	    local saved_offset = offset -- in case there is not enough data in buffer and we must rewind
      
      local msgtype = buffer(offset, 1)
      offset = offset + 1
      local remain_length = 0 
      offset, remain_length = lengthDecode(buffer, offset)

      local msgindex = msgtype:bitfield(0,4)

      if(msgindex == 1) then -- CONNECT
        local subtree = tree:add(MQTTPROTO, buffer())
        local fixheader_subtree = subtree:add("Fixed Header", nil)

        subtree:append_text(", Message Type: " .. msg_types[msgindex])
        pinfo.cols.info:set(msg_types[msgindex])

        fixheader_subtree:add(f.message_type, msgtype)
        fixheader_subtree:add(f.dup, msgtype)
        fixheader_subtree:add(f.qos, msgtype)
        fixheader_subtree:add(f.retain, msgtype)

        fixheader_subtree:add(f.remain_length, remain_length)

        local fixhdr_qos = msgtype:bitfield(5,2)
        subtree:append_text(", QoS: " .. fixhdr_qos)
        
        local varheader_subtree = subtree:add("Variable Header", nil)

        local name_len = buffer(offset, 2):uint()
        offset = offset + 2
        local name = buffer(offset, name_len)
        offset = offset + name_len
        local version = buffer(offset, 1)
        offset = offset + 1
        local flags = buffer(offset, 1)
        offset = offset + 1
        local keepalive = buffer(offset, 2)
        offset = offset + 2

        varheader_subtree:add(f.connect_protocol_name, name)
        varheader_subtree:add(f.connect_protocol_version, version)

        local flags_subtree = varheader_subtree:add("Flags", nil)
        flags_subtree:add(f.connect_username, flags)
        flags_subtree:add(f.connect_password, flags)
        flags_subtree:add(f.connect_will_retain, flags)
        flags_subtree:add(f.connect_will_qos, flags)
        flags_subtree:add(f.connect_will, flags)
        flags_subtree:add(f.connect_clean_session, flags)

        varheader_subtree:add(f.connect_keep_alive, keepalive)

        local payload_subtree = subtree:add("Payload", nil)
        -- Client ID
        local clientid_len = buffer(offset, 2):uint()
        offset = offset + 2
        local clientid = buffer(offset, clientid_len)
        offset = offset + clientid_len
        payload_subtree:add(f.connect_payload_clientid, clientid)
        -- Flags
        if(flags:bitfield(0) == 1) then -- Username flag is true
          local username_len = buffer(offset, 2):uint()
          offset = offset + 2
          local username = buffer(offset, username_len)
          offset = offset + username_len
          payload_subtree:add(f.connect_payload_username, username)
        end

        if(flags:bitfield(1) == 1) then -- Password flag is true
          local password_len = buffer(offset, 2):uint()
          offset = offset + 2
          local password = buffer(offset, password_len)
          offset = offset + password_len
          payload_subtree:add(f.connect_payload_password, password)
        end
        
      elseif(msgindex == 2) then -- CONNACK
          local subtree = tree:add(MQTTPROTO, buffer())
        local fixheader_subtree = subtree:add("Fixed Header", nil)

        subtree:append_text(", Message Type: " .. msg_types[msgindex])
        -- pinfo.cols.info:set(msg_types[msgindex])

        fixheader_subtree:add(f.message_type, msgtype)
        fixheader_subtree:add(f.dup, msgtype)
        fixheader_subtree:add(f.qos, msgtype)
        fixheader_subtree:add(f.retain, msgtype)

        fixheader_subtree:add(f.remain_length, remain_length)

        local fixhdr_qos = msgtype:bitfield(5,2)
        subtree:append_text(", QoS: " .. fixhdr_qos)
        
        local varheader_subtree = subtree:add("Variable Header", nil)


        local unused = buffer(offset, 1)
        offset = offset + 1
        local return_code = buffer(offset, 1):uint()
        local return_text = connack_return_reasons[return_code]
        pinfo.cols.info:set(msg_types[msgindex] .. ", " .. return_text)
        varheader_subtree:add(f.connack_code, return_code)
        varheader_subtree:add(f.connack_reason, return_text)

        local payload_subtree = subtree:add("Payload", nil)
        while(offset < buffer:len()) do
          local qos = buffer(offset, 1)
          offset = offset + 1
          payload_subtree:add(f.suback_qos, qos);
        end
        
      elseif(msgindex == 3) then -- PUBLISH
        local varhdr_init = offset -- For calculating variable header size

        local topic_len = buffer(offset, 2):uint()
        offset = offset + 2
        local topic = buffer(offset, topic_len)
        offset = offset + topic_len

        local message_id
        local fixhdr_qos = msgtype:bitfield(5,2)
        if(fixhdr_qos > 0) then
          message_id = buffer(offset, 2)
          offset = offset + 2
        end

        -- Data
        -- remain_len: number of MQTT bytes specified to follow fixed header
        -- data_len:   number of MQTT bytes specified to follow variable header
        local data_len = remain_length - (offset - varhdr_init)

        -- Check to see if buffer holds enough data;
        -- if not, request another segment
        if(buffer:len() - offset < data_len) then
          pinfo.desegment_len = data_len - (buffer:len()-offset)
          pinfo.desegment_offset = saved_offset
          return
        end
        
        -- we have enough data, so create the subtree
        local subtree = tree:add(MQTTPROTO, buffer(saved_offset, remain_length + 2))
        local fixheader_subtree = subtree:add("Fixed Header", nil)

        subtree:append_text(", Message Type: " .. msg_types[msgindex])
        pinfo.cols.info:set(msg_types[msgindex])

        fixheader_subtree:add(f.message_type, msgtype)
        fixheader_subtree:add(f.dup, msgtype)
        fixheader_subtree:add(f.qos, msgtype)
        fixheader_subtree:add(f.retain, msgtype)

        fixheader_subtree:add(f.remain_length, remain_length)

        local fixhdr_qos = msgtype:bitfield(5,2)
        subtree:append_text(", QoS: " .. fixhdr_qos)
        
        local varheader_subtree = subtree:add("Variable Header", nil)
        varheader_subtree:add(f.publish_topic, topic)
        if(fixhdr_qos > 0) then
          varheader_subtree:add(f.publish_message_id, message_id)
        end
        local payload_subtree = subtree:add("Payload", nil)
      
        local data = buffer(offset, data_len)
        offset = offset + data_len
        payload_subtree:add(f.publish_data, data)
        
        if(buffer:len() == offset) then
          return remain_length + 2
        end

      elseif(msgindex == 8) then -- SUBSCRIBE
        local subtree = tree:add(MQTTPROTO, buffer())
        local fixheader_subtree = subtree:add("Fixed Header", nil)

        subtree:append_text(", Message Type: " .. msg_types[msgindex])
        pinfo.cols.info:set(msg_types[msgindex])

        fixheader_subtree:add(f.message_type, msgtype)
        fixheader_subtree:add(f.dup, msgtype)
        fixheader_subtree:add(f.qos, msgtype)
        fixheader_subtree:add(f.retain, msgtype)

        fixheader_subtree:add(f.remain_length, remain_length)

        local fixhdr_qos = msgtype:bitfield(5,2)
        subtree:append_text(", QoS: " .. fixhdr_qos)
        
        local varheader_subtree = subtree:add("Variable Header", nil)

        local message_id = buffer(offset, 2)
        offset = offset + 2
        varheader_subtree:add(f.subscribe_message_id, message_id)

        local payload_subtree = subtree:add("Payload", nil)
        while(offset < buffer:len()) do
          local topic_len = buffer(offset, 2):uint()
          offset = offset + 2
          local topic = buffer(offset, topic_len)
          offset = offset + topic_len
          local qos = buffer(offset, 1)
          offset = offset + 1

          payload_subtree:add(f.subscribe_topic, topic)
          payload_subtree:add(f.subscribe_qos, qos)
        end
        
      elseif(msgindex == 9) then --SUBACK
        local subtree = tree:add(MQTTPROTO, buffer())
        local fixheader_subtree = subtree:add("Fixed Header", nil)

        subtree:append_text(", Message Type: " .. msg_types[msgindex])
        pinfo.cols.info:set(msg_types[msgindex])

        fixheader_subtree:add(f.message_type, msgtype)
        fixheader_subtree:add(f.dup, msgtype)
        fixheader_subtree:add(f.qos, msgtype)
        fixheader_subtree:add(f.retain, msgtype)

        fixheader_subtree:add(f.remain_length, remain_length)

        local fixhdr_qos = msgtype:bitfield(5,2)
        subtree:append_text(", QoS: " .. fixhdr_qos)
        
        local varheader_subtree = subtree:add("Variable Header", nil)

        local message_id = buffer(offset, 2)
        offset = offset + 2
        varheader_subtree:add(f.suback_message_id, message_id)

        local payload_subtree = subtree:add("Payload", nil)
        while(offset < buffer:len()) do
          local qos = buffer(offset, 1)
          offset = offset + 1
          payload_subtree:add(f.suback_qos, qos);
        end
        
      else
        local subtree = tree:add(MQTTPROTO, buffer())
        local fixheader_subtree = subtree:add("Fixed Header", nil)

        subtree:append_text(", Message Type: " .. msg_types[msgindex])
        pinfo.cols.info:set(msg_types[msgindex])

        fixheader_subtree:add(f.message_type, msgtype)
        fixheader_subtree:add(f.dup, msgtype)
        fixheader_subtree:add(f.qos, msgtype)
        fixheader_subtree:add(f.retain, msgtype)

        fixheader_subtree:add(f.remain_length, remain_length)

        local fixhdr_qos = msgtype:bitfield(5,2)
        subtree:append_text(", QoS: " .. fixhdr_qos)
        
        if((buffer:len()-offset) > 0) then
          local payload_subtree = subtree:add("Payload", nil)
          payload_subtree:add(f.payload_data, buffer(offset, buffer:len()-offset))
        end
        
        -- if we get here, then there was enough data to dissect
        -- a complete MQTT PDU
        return true
      end
	  
	  
	  return enough_data
	end
	
	-- The dissector function
	function MQTTPROTO.dissector(buffer, pinfo, tree)
		pinfo.cols.protocol = "MQTT"
		
		local enough_data = true -- until we learn otherwise
		
		repeat
      -- local success, result = xpcall(dissect_mqtt_pdus(buffer, pinfo, tree), function (msg) return msg..'\n'..debug.traceback()..'\n' end)
      local success = pcall(dissect_mqtt_pdus(buffer, pinfo, tree))
      debug("status = " .. tostring(success))
      
      -- dissect_mqtt_pdus(buffer, pinfo, tree)

      -- TODO: check status, revise loop logic, set appropriate return values of pinfo
      if pinfo.desegment_len ~= DESEGMENT_ONE_MORE_SEGMENT then
        -- We have dissected one or more complete MQTT PDUs, and there
        -- is no more data to dissect, so we are done.
        return
      end
		until not enough_data 
		
		-- Not enough data in this TCP segment to complete MQTT PDU,
		-- so signal wireshark to invoke us again with more data.
		--
		-- pinfo will be appropriately set
		--
    return		
	end

	-- Register the dissector
	local tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(1883, MQTTPROTO)

end
