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

require "fluent/plugin/input"
require 'cool.io'
require 'fluent/plugin/socket_util'
# require_relative 'parser_netflowipfix'
require_relative 'parser_netflow_v5'
require_relative 'parser_netflow_v9'
require_relative 'netflowipfix_records'
require_relative 'vash'

module Fluent
	module Plugin
		class NetflowipfixInput < Fluent::Plugin::Input
			Fluent::Plugin.register_input("netflowipfix", self)

      config_param :cache_ttl, :integer, default: 4000
      config_param :definitions, :string, default: nil

			config_param :debug, :bool, default: false
			config_param :port, :integer, default: 5140
			config_param :bind, :string, default: '0.0.0.0'
			config_param :tag, :string
			config_param :protocol_type, default: :udp do |val|
				case val.downcase
				when 'udp'
					:udp
				else
					raise ConfigError, "netflow input protocol type should be 'udp'"
				end
			end # config_param :protocol_type

			def configure(conf)
				super
				@nbpackets = 0
				@parser_v5 = ParserNetflowv5.new
				@parser_v9 = ParserNetflowv9.new
				@parser_v9.configure(@cache_ttl, @definitions)
				@parser_v10 = ParserIPfixv10.new
				@parser_v10.configure(@cache_ttl, @definitions)
			end # def configure

			def start
				@loop = Coolio::Loop.new
				@handler = listen(method(:receive_data))
				@loop.attach(@handler)
				@thread = Thread.new(&method(:run))
			end # def start

			def shutdown
				@loop.watchers.each { |w| w.detach }
				@loop.stop
				@handler.close
				@thread.join
			end # def shutdown

			def run
				@loop.run
				rescue => e
					log.error "unexpected error", error_class: e.class, error: e.message
					log.error_backtrace
			end # def run

			protected

			def receive_data(host, data)
				# if (@debug) 
				log.on_debug { log.debug "received logs", :host => host, :data => data }
				call(data, host) { |time, record|
				unless time && record
					log.warn "pattern not match: #{data.inspect}"
					return
				end

#			if (@debug) log.info "ready to emit ", time:time, tag:@tag

				record['host'] = host
				router.emit(@tag, EventTime.new(time), record)
				} # call
				rescue => e
				log.warn "unexpected error on parsing", data: data.dump, error_class: e.class, error: e.message
				log.warn_backtrace
			end # def receive_data

			private

			def listen(callback)
				log.info "listening netflow socket on #{@bind}:#{@port} with #{@protocol_type}"
				if @protocol_type == :udp
					@usock = SocketUtil.create_udp_socket(@bind)
					@usock.bind(@bind, @port)
					UdpHandler.new(@usock, callback)
				else
					Coolio::TCPServer.new(@bind, @port, TcpHandler, log, callback)
				end
			end # def listen
    
			def call(payload, host=nil, &block)
				version,_ = payload[0,2].unpack('n')
				@nbpackets += 1
				#	nb = @nbpackets
				if (@debug) 
					log.debug "Packet #{@nbpackets} with version #{version}"
				end
				case version
					when 5          
						packet = Netflow5Packet.read(payload)
						@parser_v5.handle_v5(host, packet, block)
					when 9
						packet = Netflow9Packet.read(payload)
						@parser_v9.handle_v9(host, packet, block)
					when 10
						packet = Netflow10Packet.read(payload)
						@parser_v10.handle_v10(host, packet, block)
					else
						$log.warn "Unsupported Netflow version v#{version}: #{version.class}"
				end # case
			end # def call

		end # class NetflowipfixInput

		class UdpHandler < Coolio::IO
			def initialize(io, callback)
				super(io)
				@io = io
				@callback = callback
			end # def initialize

			def on_readable
				msg, addr = @io.recvfrom_nonblock(4096)
				@callback.call(addr[3], msg)
				rescue => e
					log.error "unexpected error on reading from socket", error_class: e.class, error: e.message
				log.error_backtrace
			end # def on_readable
		end # class UdpHandler


	end # module Plugin
end # module Fluent



    


=begin
=end
