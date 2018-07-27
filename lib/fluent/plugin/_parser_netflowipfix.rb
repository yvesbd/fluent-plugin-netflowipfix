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
    class NetflowipfixParser < Fluent::Plugin::Parser
      Fluent::Plugin.register_parser("netflowipfix", self)

      config_param :switched_times_from_uptime, :bool, default: false
      config_param :cache_ttl, :integer, default: 4000
      config_param :versions, :array, default: [5, 9, 10]
      config_param :definitions, :string, default: nil

      # Cisco NetFlow Export Datagram Format
      # http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
      # Cisco NetFlow Version 9 Flow-Record Format
      # http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html

#      def parse(text)
#        yield time, record
#      end
      
      def configure(conf)
        super
        @templates9 = Vash.new()
        @templates10 = Vash.new()
        @samplers_v9 = Vash.new()
        @samplers_v10 = Vash.new()
	@nbpackets = 0
        # Path to default Netflow v9 field definitions
        filename9 = File.expand_path('../netflow_fields.yaml', __FILE__)

        begin
          @fields9 = YAML.load_file(filename9)
        rescue => e
          raise ConfigError, "Bad syntax in definitions file #{filename9}, error_class = #{e.class.name}, error = #{e.message}"
        end

	       
	# Path to default Netflow v10 field definitions
        filename10 = File.expand_path('../ipfix_fields.yaml', __FILE__)

        begin
          @fields10 = YAML.load_file(filename10)
        rescue => e
          raise ConfigError, "Bad syntax in definitions file #{filename10}, error_class = #{e.class.name}, error = #{e.message}"
        end

        # TODO: likely remove or modify to support v9 v10
        # Allow the user to augment/override/rename the supported Netflow fields
        if @definitions
          raise ConfigError, "definitions file #{@definitions} doesn't exist" unless File.exist?(@definitions)
          begin
            @fields9['option'].merge!(YAML.load_file(@definitions))
          rescue => e
            raise ConfigError, "Bad syntax in definitions file #{@definitions}, error_class = #{e.class.name}, error = #{e.message}"
          end
        end
      end # def configure

      def call(payload, host=nil, &block)
        version,_ = payload[0,2].unpack('n')
	@nbpackets += 1
	nb = @nbpackets
        $log.debug "Packet #{nb} with version #{version}"
        $log.info "Packet #{nb} with version #{version}"
        case version
        when 5
          packet = Netflow5Packet.read(payload)
          handle_v5(host, packet, block)
        when 9
          packet = Netflow9Packet.read(payload)
          handle_v9(host, packet, block)
        when 10
          packet = Netflow10Packet.read(payload)
          handle_v10(host, packet, block)
        else
          $log.warn "Unsupported Netflow version v#{version}: #{version.class}"
        end # case
      end # def call

      private

      def handle_v5(host, packet, block)
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

      def handle_v9(host, pdu, block)
        pdu.records.each do |flowset|
          case flowset.flowset_id
          when 0
            handle_flowset_template(host, pdu, flowset, @templates9, @fields9)
          when 1
            handle_flowset_options_template(host, pdu, flowset, @templates9, @fields9)
          when 256..65535
            handle_flowset_data(host, pdu, flowset, block, @templates9, @fields9, 9)
          else
            $log.warn 'v9 Unsupported flowset', flowset_id: flowset.flowset_id
          end # case 
        end # do
      end # def
      
      def handle_v10(host, pdu, block)
        pdu.records.each do |flowset|
          case flowset.flowset_id
          when 2
            handle_flowset_template(host, pdu, flowset, @templates10, @fields10)
          when 3
            handle_flowset_options_template(host, pdu, flowset, @templates10, @fields10)
          when 256..65535
            handle_flowset_data(host, pdu, flowset, block, @templates10, @fields10, 10)
          else
            $log.warn 'v10 Unsupported set', set_id: flowset.set_id
          end # case
        end # do
      end # def


      def handle_flowset_template(host, pdu, flowset, templates, p_fields)
        $log.warn 'handle_flowset_template:', host, ';', pdu.version
        flowset.flowset_data.templates.each do |template|
        $log.warn 'added template:', template.template_id, ',ver:',pdu.version
        catch (:field) do
          fields = []
          template.template_fields.each do |field|
            # $log.warn 'v9 added field:', field.field_type 
            entry = netflowipfix_field_for(field.field_type, field.field_length, p_fields)
            throw :field unless entry
            fields += entry
          end # do field
          # We get this far, we have a list of fields
          key = "#{host}|#{pdu.source_id}|#{template.template_id}"
          templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, fields: fields)
          # $log.info("cache_ttl is #{@cache_ttl}")
          # $log.info("v9 added template,flowset.source_id|template.template_id is #{key}")
          # Purge any expired templates
          templates.cleanup!
        end # catch
      end 
    end 
    
      def netflowipfix_field_for(type, length, p_fields, category='option')
        unless field = p_fields[category][type]
          $log.warn "Skip unsupported field", type: type, length: length
#          [field + [{length: length, trim_padding: true}]]
          return [[:skip, nil, {length: length}]]
#          [:skip, nil, {length: length}]
        end # unless

        unless field.is_a?(Array)
          $log.warn "Skip non-Array definition", fields: field
          return [[:skip, nil, {length: length}]]
        end # unless

        # Small bit of fixup for numeric value, :skip or :string field length, which are dynamic
        case field[0]
        when Integer
          [[uint_field(length, field[0]), field[1]]]
        when :skip
          [field + [nil, {length: length}]]
        when :string
          [field + [{length: length, trim_padding: true}]]
        when "octetArray"
          $log.warn "v10_paddingOctets ", type:field[0], name:field[1], len:length
          # [field + [nil, {length: length}]]
#          [[uint_field(length, 2), field[1]]]
#	  [[uint_field(length, 0), field[1]]]
oField = octetArray(length)
$log.info "octet field ", oField
#	  [[octetArray(length), field[1]]]
	  [[oField, field[1]]]

#          [field + [{length: length, trim_padding: true}]]
#	[BinData::String.new(:length => lenth), field[1]]
#          [:skip, nil, {length: length}]

        else
          [field]
        end # case
      end #def

      NETFLOWIPFIX_FIELD_CATEGORIES = ['scope', 'option']
        
      def handle_flowset_options_template(host, pdu, flowset, templates, p_fields)
        flowset.flowset_data.templates.each do |template|
          catch (:field) do
            fields = []
        
            NETFLOWIPFIX_FIELD_CATEGORIES.each do |category|
              template["#{category}_fields"].each do |field|
              entry = netflowipfix_field_for(field.field_type, field.field_length, p_fields, category)
              throw :field unless entry
              fields += entry
            end # do field
          end # do category
        
          # We get this far, we have a list of fields
          key = "#{host}|#{pdu.source_id}|#{template.template_id}"
          templates[key, @cache_ttl] = BinData::Struct.new(endian: :big, fields: fields)
          # Purge any expired templates
          templates.cleanup!
        end # catch
      end # do templates
    end # def
        
    FIELDS_FOR_COPY_v9_10 = ['version', 'flow_seq_num']
    
      def handle_flowset_data(host, packet, flowset, block, templates, fields, ver)
        template_key = "#{host}|#{packet.source_id}|#{flowset.flowset_id}"
        # $log.warn 'added data template:', template_key
        $log.warn 'handle_flowset_data template:', template_key
        template = templates[template_key]
        if ! template
          $log.warn 'No matching template for',
                    host: host, source_id: packet.source_id, flowset_id: flowset.flowset_id
          return
        end

$log.info "v #{packet.version} flowset ", $flowset

        if packet.version == 9
	els
	end

        length = flowset.flowset_length - 4
#        length = flowset.flowset_length

        if packet.version == 9
          # Template shouldn't be longer than the flowset and there should
          # be at most 3 padding bytes
#          if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 3)
          if template.num_bytes > flowset.flowset_length or ! (flowset.flowset_length % template.num_bytes).between?(0, 3)
            $log.warn "v9 Template length doesn't fit cleanly into flowset",
                      template_id: flowset.flowset_id, template_length: template.num_bytes, flowset_length: length
#            return
          end

          array = BinData::Array.new(type: template, initial_length: length / template.num_bytes)
        elsif packet.version == 10
#          array = BinData::Array.new(type: template, initial_length: length / template.num_bytes)
          array = BinData::Array.new(type: template, :read_until => :eof)
        end


        fields = array.read(flowset.flowset_data)
        fields.each do |r|
          #if is_sampler?(r)
          #  sampler_key = "#{host}|#{pdu.source_id}|#{r.flow_sampler_id}"
          #  register_sampler_v9 sampler_key, r
          #  next
          #end

          time = packet.unix_sec  # TODO: Fluent::EventTime (see: forV5)
          event = {}

          # Fewer fields in the v9 header
          FIELDS_FOR_COPY_v9_10.each do |f|
            event[f] = packet[f]
          end

          event['flowset_id'] = flowset.flowset_id

          r.each_pair {|k,v| event[k.to_s] = v }
          unless @switched_times_from_uptime
            if packet.version == 9
              event['first_switched'] = format_for_switched(msec_from_boot_to_time(event['first_switched'], packet.uptime, time, 0))
              event['last_switched']  = format_for_switched(msec_from_boot_to_time(event['last_switched'] , packet.uptime, time, 0))
            elsif packet.version == 10
              event['first_switched'] = format_for_switched(msec_from_boot_to_time(event['first_switched'], packet.unix_sec, time, 0))
              event['last_switched']  = format_for_switched(msec_from_boot_to_time(event['last_switched'] , packet.unix_sec, time, 0))
            end
          end

          #if sampler_id = r['flow_sampler_id']
          #  sampler_key = "#{host}|#{pdu.source_id}|#{sampler_id}"
          #  if sampler = @samplers_v9[sampler_key]
          #    event['sampling_algorithm'] ||= sampler['flow_sampler_mode']
          #    event['sampling_interval'] ||= sampler['flow_sampler_random_interval']
          #  end
          #end

          block.call(time, event)
        end
      end

      # covers Netflow v9 and v10 (a.k.a IPFIX)
      def is_sampler?(record)
        record['flow_sampler_id'] && record['flow_sampler_mode'] && record['flow_sampler_random_interval']
      end


      def uint_field(length, default)
        # If length is 4, return :uint32, etc. and use default if length is 0
$log.warn        ("uint" + (((length > 0) ? length : default) * 8).to_s)
        ("uint" + (((length > 0) ? length : default) * 8).to_s).to_sym
      end # def uint_field


def octetArray(length)
#	("
$log.warn "octetArray", len:length
#$log.warn        ("uint" + (((length > 0) ? length : default) * 8).to_s)
#      uint_field(length, 0)
        ("OctetArray" + length.to_s).to_sym
	case length
	when 1,"1"
	("OctetArray1").to_sym
	when 2,"2"
	("OctetArray2").to_sym
	else
$log.error "No octet array of #{length} bytes"
	end
end #octetArray











    end # class NetflowipfixParser
  end # module Plugin
end # module Fluent     
      
