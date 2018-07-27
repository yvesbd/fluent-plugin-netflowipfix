require "bindata"

module Fluent
  module Plugin
		class NetflowipfixInput < Fluent::Plugin::Input


			class IP4Addr < BinData::Primitive
				endian :big
				uint32 :storage

				def set(val)
					ip = IPAddr.new(val)
					if ! ip.ipv4?
					  raise ArgumentError, "invalid IPv4 address '#{val}'"
					end
					self.storage = ip.to_i
				end # set

				def get
					IPAddr.new_ntoh([self.storage].pack('N')).to_s
				end # get
			end # class


			class IP6Addr < BinData::Primitive
				endian  :big
				uint128 :storage

				def set(val)
				  ip = IPAddr.new(val)
				  if ! ip.ipv6?
					raise ArgumentError, "invalid IPv6 address `#{val}'"
				  end
				  self.storage = ip.to_i
				end

				def get
				  IPAddr.new_ntoh((0..7).map { |i|
					  (self.storage >> (112 - 16 * i)) & 0xffff
					}.pack('n8')).to_s
				end
			end

  
			class MacAddr < BinData::Primitive
				endian :big
				array :bytes, type: :uint8, initial_length: 6

				def set(val)
				  ints = val.split(/:/).collect { |int| int.to_i(16) }
				  self.bytes = ints
				end

				def get
				  self.bytes.collect { |byte| byte.value.to_s(16).rjust(2,'0') }.join(":")
				end
			end

			class MplsLabel < BinData::Primitive
				endian :big
				bit20 :label
				bit3  :exp
				bit1  :bottom
				def set(val)
				  self.label = val >> 4
				  self.exp = (val & 0b1111) >> 1
				  self.bottom = val & 0b1
				end
				def get
					self.label
				end
			end

			class Header < BinData::Record
				endian :big
				uint16 :version
			end

			class Netflow5Packet < BinData::Record
				endian :big
				uint16 :version
				uint16 :flow_records
				uint32 :uptime
				uint32 :unix_sec
				uint32 :unix_nsec
				uint32 :flow_seq_num
				uint8  :engine_type
				uint8  :engine_id
				bit2   :sampling_algorithm
				bit14  :sampling_interval
				array  :records, initial_length: :flow_records do
				  ip4_addr :ipv4_src_addr
				  ip4_addr :ipv4_dst_addr
				  ip4_addr :ipv4_next_hop
				  uint16   :input_snmp
				  uint16   :output_snmp
				  uint32   :in_pkts
				  uint32   :in_bytes
				  uint32   :first_switched
				  uint32   :last_switched
				  uint16   :l4_src_port
				  uint16   :l4_dst_port
				  skip     length: 1
				  uint8    :tcp_flags # Split up the TCP flags maybe?
				  uint8    :protocol
				  uint8    :src_tos
				  uint16   :src_as
				  uint16   :dst_as
				  uint8    :src_mask
				  uint8    :dst_mask
				  skip     length: 2
				end
			end

			# Template format for v9 and v10 - shared field must use same name to simplify code
			class Template9 < BinData::Record
				endian :big
				array  :templates, read_until: lambda { array.num_bytes == flowset_length - 4 } do
				  uint16 :template_id
				  uint16 :field_count
				  array  :template_fields, initial_length: :field_count do
					uint16 :field_type
					uint16 :field_length
				  end # array fields
				end # array templates
			end #class

			class Template10 < BinData::Record
				endian :big
				array  :templates, read_until: lambda { array.num_bytes == flowset_length - 4 } do
				  uint16 :template_id
				  uint16 :field_count
				  array  :template_fields, initial_length: :field_count do
					uint16 :field_type
					uint16 :field_length
						# TODO: if upperbit (enterprise_bit) is set, then we have an enterprise # of 4 bytes (uint32)
					  uint32 :enterpriseNumber, :onlyif => lambda { field_type >= 0x8000 }
				  end # array fields
				end # array templates
			end #class

			class Option9 < BinData::Record
				endian :big
				array  :templates, read_until: lambda { flowset_length - 4 - array.num_bytes <= 2 } do
				  uint16 :template_id
				  uint16 :scope_length
				  uint16 :option_length
				  array  :scope_fields, initial_length: lambda { scope_length / 4 } do
					uint16 :field_type
					uint16 :field_length
				  end # array scope_fields
				  array  :option_fields, initial_length: lambda { option_length / 4 } do
					uint16 :field_type
					uint16 :field_length
				  end # array option_fields
				end # array templates
				skip   length: lambda { templates.length.odd? ? 2 : 0 }
			end #class

			class Option10 < BinData::Record
				endian :big
				array  :templates, read_until: lambda { flowset_length - 4 - array.num_bytes <= 2 } do
				  uint16 :template_id
				  uint16 :field_count
				  uint16 :scope_field_count
				  array  :scope_fields, initial_length: :scope_field_count do
					uint16 :field_type
					uint16 :field_length
						  # TODO: if upperbit (enterprise_bit) is set, then we have an enterprise # of 4 bytes (uint32)
					  uint32 :enterpriseNumber, :onlyif => lambda { field_type >= 0x8000 }
				  end # array scope_fields
				  array  :option_fields, initial_length: lambda { field_count - scope_field_count } do
					uint16 :field_type
					uint16 :field_length
						  # TODO: if upperbit (enterprise_bit) is set, then we have an enterprise # of 4 bytes (uint32)
					  uint32 :enterpriseNumber, :onlyif => lambda { field_type >= 0x8000 }
				  end # array option_fields
				end # array templates
			end #class

			class Netflow9Packet < BinData::Record
				endian :big
				uint16 :version
				uint16 :flow_records
				uint32 :uptime
				uint32 :unix_sec
				uint32 :flow_seq_num
				uint32 :source_id
				array  :records, read_until: :eof do
				  uint16 :flowset_id
				  uint16 :flowset_length
				  choice :flowset_data, selection: :flowset_id do
					template9 0
					option9   1
					string           :default, read_length: lambda { flowset_length - 4 }
				  end # choice
				end # array records
			end #class

			class Netflow10Packet < BinData::Record
				endian :big
				uint16 :version
				uint16 :ipfix_length #flow_records
				uint32 :unix_sec #export_time #uptime
				# uint32 :
				uint32 :flow_seq_num # seq_num
				uint32 :source_id # observation_domain_id
				array  :records, read_until: :eof do
					# set header
				  uint16 :flowset_id # 2 = template, 3 = options, >= 256 = data sets
				  uint16 :flowset_length # in octets
					  # record
				  choice :flowset_data, selection: :flowset_id do
					template10 2
					option10   3
					string           :default, read_length: lambda { flowset_length - 4 }
				  end # choice
				end # array 
			end # class


			class OctetArray1 < BinData::Array
				endian :big
				uint8 :storage
			end

			class OctetArray2 < BinData::Primitive
				array :bytes, type: :uint8, initial_length: 2

				def set(val)
				  ints = val.split(/:/).collect { |int| int.to_i(16) }
				  self.bytes = ints
				end

				def get
				  self.bytes.collect { |byte| byte.value.to_s(16).rjust(2,'0') }.join(":")
				end
			end

		end # class NetflowipfixInput
	end # module Plugin
end # module Fluent
