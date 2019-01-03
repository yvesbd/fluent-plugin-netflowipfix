#
# Copyright 2018-2019 Yves Desharnais
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


require "socket"
require "fluent/plugin/input"

require_relative 'parser_netflow_v5'
require_relative 'parser_netflow_v9'
require_relative 'netflowipfix_records'
require_relative 'vash'


module Fluent
  module Plugin
    class NetflowipfixInput < Fluent::Plugin::Input
      Fluent::Plugin.register_input("netflowipfix", self)
      include DetachMultiProcessMixin

class PortConnection
	def initialize(bind, port, tag, cache_ttl, definitions, queuesleep)
		@bind = bind
		@port = port
		@tag = tag
		@cache_ttl = cache_ttl
		@definitions = definitions
		@eventQueue = Queue.new
		@udpQueue = Queue.new
		@queuesleep = queuesleep
	end
	
	def bind
		@bind
	end
	def port
		@port
	end
	def tag
		@tag
	end
	
	def start
		@thread_udp = UdpListenerThread.new(@bind, @port, @udpQueue, @tag)
		@thread_parser = ParserThread.new(@udpQueue, @queuesleep, @eventQueue, @cache_ttl, @definitions)
		@thread_udp.start
		@thread_parser.start
	end # def start
	def stop
			@thread_udp.close
			@thread_udp.join
			@thread_parser.close
			@thread_parser.join
	end # def stop
	
	def event_pop
		@eventQueue.pop
	end
	
	def event_queue_length
		@eventQueue.length
	end


#	def udpqueue_pop
#		@udpQueue.pop
#	end
	
#	def udpqueue_length
#		@udpQueue.length
#	end
end #class PortConnection

		config_param :tag, :string
		config_param :port, :integer, default: nil
		config_param :bind, :string, :default => '0.0.0.0'
		config_param :queuesleep, :integer, default: 10

		def configure(conf)
			super
			$log.debug "NetflowipfixInput::configure: #{@bind}:#{@port}"
			@@connections ||=  {}
			if @@connections.nil?
			end
			@@connections[@port] = PortConnection.new(@bind, @port, @tag, @cache_ttl, @definitions, @queuesleep)
			log.debug "NetflowipfixInput::configure NB=#{@@connections.length}"	
			@total = 0
		end
		
		def start
			super
			
			$log.debug "NetflowipfixInput::start NB=#{@@connections.length}"	
			if @@connections.nil?
			else
				@@connections.each do | port, conn |
					$log.debug "start listening UDP on #{conn.bind}:#{conn.port}"
					conn.start				
				end
			end
			
			
#			@eventQueue = Queue.new
#			@udpQueue = Queue.new
#			@thread_udp = UdpListenerThread.new(@bind, @port, @udpQueue)
#			@thread_parser = ParserThread.new(@udpQueue, @queuesleep, @eventQueue, @cache_ttl, @definitions)
#			@thread_udp.start
#			@thread_parser.start
			waitForEvents
		end

		def shutdown
			super
			$log.debug "NetflowipfixInput::shutdown NB=#{@@connections.length}"	
			if @@connections.nil?
			else
#				$log.debug "listening UDP on #{@bind}:#{@port}"
#				@connections[@port].stop
				@@connections.each do | port, conn |
					$log.debug "shutdown listening UDP on #{conn.bind}:#{conn.port}"
					conn.stop				
				end
				@@connections = nil
			end

#			@thread_udp.close
#			@thread_udp.join
#			@thread_parser.close
#			@thread_parser.join
		end		
		

		def waitForEvents
#		puts "Main::run begin #{@eventQueue.length}"
			loop do
					@@connections.each do | port, conn |
						if (conn.event_queue_length > 0) 
							$log.debug "waitForEvents: #{conn.bind}:#{conn.port}"
							ar = conn.event_pop			
							time = ar[0]
							record = ar[1]
							router.emit(conn.tag, EventTime.new(time.to_i), record)
						end
					end
					sleep(@queuesleep)

#				if @eventQueue.length > 0
				
				
#					ar = @eventQueue.pop
#					time = ar[0]
#					record = ar[1]
#					router.emit(@tag, EventTime.new(time.to_i), record)


#		puts "Main::pop before #{@eventQueue.length} #{@tag} #{time}" # #{record.to_s}"
#		puts "Main::pop after  #{@eventQueue.length}"
#				else
#				end
			end
#		puts "Main::run end #{@eventQueue.length}"

		end

		private


class UdpListenerThread

	def initialize(bind, port, udpQueue, tag)
		@port = port
		@udpQueue = udpQueue
		@udp_socket = UDPSocket.new
		@udp_socket.bind(bind, port)
		@total = 0
		@tag = tag
	end

	def start
		@thread = Thread.new(&method(:run))
		puts "UdpListenerThread::start"
	end 
	
	def close
			@udp_socket.close
	end
	
	def join
			@thread.join
	end
	
	
	def run
			loop do
				msg, sender =  @udp_socket.recvfrom(4096)
				@total = @total + msg.length
#		puts "UdpListenerThread::recvfrom #{msg.length} bytes for #{@total} total on UDP/#{@port}"
#				log.debug "Received #{msg.length} bytes for #{@total} total"
				record = {}
				record["message"] = msg
				record["length"] = msg.length
				record["total"] = @total
				record["sender"] = sender
				record["port"] = @port
#				time = EventTime.new()
				time = Time.now.getutc
#				router.emit(@tag, EventTime.new(), record)
				@udpQueue << [time, record]
			end
	end
end # class UdpListenerThread
		
class ParserThread
	def initialize(udpQueue, queuesleep, eventQueue, cache_ttl, definitions)
		@udpQueue = udpQueue
		@queuesleep = queuesleep
		@eventQueue = eventQueue

		@parser_v5 = NetflowipfixInput::ParserNetflowv5.new
		@parser_v9 = NetflowipfixInput::ParserNetflowv9.new
		@parser_v10 = NetflowipfixInput::ParserIPfixv10.new

		@parser_v9.configure(cache_ttl, definitions)
		@parser_v10.configure(cache_ttl, definitions)
	end
	def start
		@thread = Thread.new(&method(:run))
		puts "ParserThread::start"
	end 
	
	def close
	end
	
	def join
			@thread.join
	end
	
	def run
#		puts "ParserThread::run start #{@udpQueue.length}"

		loop do
			if @udpQueue.length == 0
#		puts "ParserThread::run sleep #{@queuesleep}"
				sleep(@queuesleep)

			else
				block = method(:emit)
#block = nil
				ar = @udpQueue.pop
				time = ar[0]
				msg = ar[1]
				payload = msg["message"]
				host = msg["sender"]
				
				version,_ = payload[0,2].unpack('n')
#		puts "ParserThread::pop #{@udpQueue.length} v#{version}"


				case version
					when 5          
						packet = NetflowipfixInput::Netflow5Packet.read(payload)
						@parser_v5.handle_v5(host, packet, block)
					when 9
						packet = NetflowipfixInput::Netflow9Packet.read(payload)
						@parser_v9.handle_v9(host, packet, block)
					when 10
						packet = NetflowipfixInput::Netflow10Packet.read(payload)
						@parser_v10.handle_v10(host, packet, block)
					else
#						$log.warn "Unsupported Netflow version v#{version}: #{version.class}"
				end # case

#				parent_call(time, record)
#				@eventQueue << [time, record]
			end
		end # loop do
	end # def run
	def emit(time, event, host = nil)
		if !host.nil?
			event["host"] = host
		end
		@eventQueue << [time, event]
# puts "ParserThread::emit #{@eventQueue.length}"
	end # def emit

end # class ParserThread


    end # class DnsCacheOuput
  end # module Plugin
end # module Fluent

