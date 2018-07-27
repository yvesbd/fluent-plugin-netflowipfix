#
# Copyright 2018 Yves Desharnais
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "fluent/plugin/parser"
require "bindata"
require 'yaml'

module Fluent
	module Plugin
		class NetflowipfixInput < Fluent::Plugin::Input
	
	
			class ParserNetflowBase
			
			private
	  
				def ipv4_addr_to_string(uint32)
					"#{(uint32 & 0xff000000) >> 24}.#{(uint32 & 0x00ff0000) >> 16}.#{(uint32 & 0x0000ff00) >> 8}.#{uint32 & 0x000000ff}"
				end

				def msec_from_boot_to_time(msec, uptime, current_unix_time, current_nsec)
					millis = uptime - msec
					seconds = current_unix_time - (millis / 1000)
					micros = (current_nsec / 1000) - ((millis % 1000) * 1000)
					if micros < 0
						seconds -= 1
						micros += 1000000
					end
					Time.at(seconds, micros)
				end # def msec_from_boot_to_time

				def format_for_switched(time)
					time.utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ".freeze)
				end # def format_for_switched(time)

				def format_for_flowSeconds(time)
					time.utc.strftime("%Y-%m-%dT%H:%M:%S".freeze)
				end # def format_for_flowSeconds(time)
		
				def format_for_flowMilliSeconds(time)
					time.utc.strftime("%Y-%m-%dT%H:%M:%S.%3NZ".freeze)
				end # def format_for_flowMilliSeconds(time)

				def format_for_flowMicroSeconds(time)
					time.utc.strftime("%Y-%m-%dT%H:%M:%S.%6NZ".freeze)
				end # def format_for_flowMicroSeconds(time)

				def format_for_flowNanoSeconds(time)
					time.utc.strftime("%Y-%m-%dT%H:%M:%S.%9NZ".freeze)
				end # def format_for_flowNanoSeconds(time)
			end # class ParserNetflow


		class ParserNetflowv5 < ParserNetflowBase

			def configure(conf)
				super
			end # def configure



      private

      def handle(host, packet, block)
        packet.records.each do |flowset|
          # handle_flowset_data(host, packet, flowset, block, null, null)

          record = {
            "version" => packet.version,
            "uptime"  => packet.uptime,
            "flow_records" => packet.flow_records,
            "flow_seq_num" => packet.flow_seq_num,
            "engine_type"  => packet.engine_type,
            "engine_id"    => packet.engine_id,
            "sampling_algorithm" => packet.sampling_algorithm,
            "sampling_interval"  => packet.sampling_interval,

            "ipv4_src_addr" => flowset.ipv4_src_addr,
            "ipv4_dst_addr" => flowset.ipv4_dst_addr,
            "ipv4_next_hop" => flowset.ipv4_next_hop,
            "input_snmp"  => flowset.input_snmp,
            "output_snmp" => flowset.output_snmp,
            "in_pkts"  => flowset.in_pkts,
            "in_bytes" => flowset.in_bytes,
            "first_switched" => flowset.first_switched,
            "last_switched"  => flowset.last_switched,
            "l4_src_port" => flowset.l4_src_port,
            "l4_dst_port" => flowset.l4_dst_port,
            "tcp_flags" => flowset.tcp_flags,
            "protocol" => flowset.protocol,
            "src_tos"  => flowset.src_tos,
            "src_as"   => flowset.src_as,
            "dst_as"   => flowset.dst_as,
            "src_mask" => flowset.src_mask,
            "dst_mask" => flowset.dst_mask
          }
          unless @switched_times_from_uptime
            record["first_switched"] = format_for_switched(msec_from_boot_to_time(record["first_switched"], packet.uptime, packet.unix_sec, packet.unix_nsec))
            record["last_switched"]  = format_for_switched(msec_from_boot_to_time(record["last_switched"] , packet.uptime, packet.unix_sec, packet.unix_nsec))
          end # unless

          time = Time.at(packet.unix_sec, packet.unix_nsec / 1000).to_i # TODO: Fluent::EventTime
          block.call(time, record)
        end # do flowset
      end # def handle_v5






    end # class ParserNetflowv5

  end # class NetflowipfixInput
  end # module Plugin
end # module Fluent     
      
