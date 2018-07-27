#
# Copyright 2018- TODO: Write your name
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

require "fluent/plugin/output"

module Fluent
  module Plugin
    class GreprouterlabelOutput < Fluent::Plugin::Output
      Fluent::Plugin.register_output("GrepRouterLabel", self)

  REGEXP_MAX_NUM = 20
    # config_param defines a parameter. You can refer a parameter via @path instance variable
    # Without :default, a parameter is required.
    # config_param :path, :string
  config_param :elselabel, :string, :default => nil
  (1..REGEXP_MAX_NUM).each {|i| config_param :"regexp#{i}",  :string, :default => nil }
  (1..REGEXP_MAX_NUM).each {|i| config_param :"label#{i}", :string, :default => nil }


      	def configure(conf)
      	  super
      	  
		@regexps = {}
		# @regexps[@input_key] = Regexp.compile(@regexp) if @input_key and @regexp
		(1..REGEXP_MAX_NUM).each do |i|
		  next unless conf["regexp#{i}"]
		  key, regexp = conf["regexp#{i}"].split(/ /, 2)
		  raise Fluent::ConfigError, "regexp#{i} does not contain 2 parameters" unless regexp
		  # raise Fluent::ConfigError, "regexp#{i} contains a duplicated key, #{key}" if @regexps[key]
		  # @regexps[key] = Regexp.compile(regexp)
		  raise Fluent::ConfigError, "no matching label#{i} for regexp#{i}" unless conf["label#{i}"]
		  @regexps[i] = [key, Regexp.compile(regexp), conf["label#{i}"]]
# $log.info "GrepRouter conf regexps:", i, key, regexp, conf["label#{i}"]
		end

      	end # def configure

      def start
      	  super
#		$log.debug "GrepRouterLabelOutput.start "
      end # def start

      def shutdown
      	  super
#		$log.debug "GrepRouterLabelOutput.shutdown "
      end # def start

      def emit(tag, es, chain)
#		$log.debug "GrepRouterLabelOutput.emit "
      	es.each do |time, record|
      		handle_record(tag, time, record)
      	end
      	chain.next
      end # def emit

    # method for non-buffered output mode
    def process(tag, es)
#		$log.debug "GrepRouterLabelOutput.process "
      	es.each do |time, record|
      		handle_record(tag, time, record)
      	end
    end
    
    def handle_record(tag, time, record)
		destLabel = ""
		@regexps.each do |i, arr|
			key = arr[0]
			regexp = arr[1]
			tag = arr[2]
			compareTo = record[key]
			if compareTo.nil? && key.include?(".")
				compareTo = record
				key.split(".").each { |k| 
					if compareTo.key?(k) 
						compareTo = compareTo[k]
					end
				}
				
			end
            if (regexp.match(compareTo.to_s))
				destLabel = tag
			end
        end #regexps.each

		if (destLabel.nil? || destLabel.empty?)
			if elselabel.nil?
				# no else tag
				else
					destLabel = elselabel
                end
        end

#			$log.debug "GrepRouter.emit ", tag:tag, label:destLabel

		if (destLabel.nil? || destLabel.empty?)
            # no match
#			$log.debug "GrepRouter.emit nomatch", tag
        else
			# change label
#			$log.debug "GrepRouter.emit changelabel:", destLabel            
#			$log.info	 "GrepRouter.emit changeLabel:", destLabel            
			label = Engine.root_agent.find_label(destLabel)
			router = label.event_router
			router.emit(tag, time, record) 
#			router.emit_stream(tag, es)
        end
    end


    end
  end
end

=begin
fluentd -c /fluentd/etc/fluent.conf -p /fluentd/plugins -vv -o /data/dnsmasq/log/fluent.3

# out_GrepRouter
require "fluent/plugin/output"


module Fluent
  module Plugin
        class GrepRouterLabelOutput < Fluent::Plugin::Output
    # First, register the plugin. NAME is the name of this plugin
    # and identifies the plugin in the configuration file.
    Fluent::Plugin.register_output('GrepRouterLabel', self)

    helpers :thread  # for try_write


  # for test
#  attr_reader :regexps
#  attr_reader :tags

	
    # This method is called before starting.
    # 'conf' is a Hash that includes configuration parameters.
    # If the configuration is invalid, raise Fluent::ConfigError.
    def configure(conf)
      super

      # You can also refer raw parameter via conf[name].
      # @path = conf['path']
		@regexps = {}
		# @regexps[@input_key] = Regexp.compile(@regexp) if @input_key and @regexp
		(1..REGEXP_MAX_NUM).each do |i|
		  next unless conf["regexp#{i}"]
		  key, regexp = conf["regexp#{i}"].split(/ /, 2)
		  raise Fluent::ConfigError, "regexp#{i} does not contain 2 parameters" unless regexp
		  # raise Fluent::ConfigError, "regexp#{i} contains a duplicated key, #{key}" if @regexps[key]
		  # @regexps[key] = Regexp.compile(regexp)
		  raise Fluent::ConfigError, "no matching label#{i} for regexp#{i}" unless conf["label#{i}"]
		  @regexps[i] = [key, Regexp.compile(regexp), conf["label#{i}"]]
# $log.info "GrepRouter conf regexps:", i, key, regexp, conf["label#{i}"]
		end

    end

    # This method is called when starting.
    # Open sockets or files here.
    def start
      super
		$log.debug "GrepRouterLabelOutput.start "
    end

    # This method is called when shutting down.
    # Shutdown the thread and close sockets or files here.
#    def shutdown
#      super
#    end


	def processRecord(tag, time,record)
		$log.debug "GrepRouterLabelOutput.processRecord ", tag, time, record
		destLabel = ""
		@regexps.each do |i, arr|
			key = arr[0]
			regexp = arr[1]
			tag = arr[2]
#	$log.info "GrepRouter.emit ", tag, time, record
#	$log.info "GrepRouter.emit ", key:key, regexp:regexp, tag:tag
#	$log.info "GrepRouter.emit ", record:record
			compareTo = record[key]
            if (regexp.match(record[key].to_s))
				destLabel = tag
			end
        end #regexps.each

		if (destLabel.nil? || destLabel.empty?)
			if elselabel.nil?
				# no else tag
				else
					destLabel = elselabel
                end
        end

		if (destLabel.nil? || destLabel.empty?)
            # no match
			$log.debug "GrepRouter.emit nomatch", tag
        else
			# change label
			$log.debug "GrepRouter.emit changelabel:", destLabel            
#			$log.info	 "GrepRouter.emit changeLabel:", destLabel            
			label = Engine.root_agent.find_label(destLabel)
			router = label.event_router
			router.emit(tag, time, record) 
        end
	end # processRecord

	def emit(tag, es, chain) 
		es.each do |time,record| 
		$log.debug "GrepRouter.emit ", tag, time, record
		processRecord(tag, time,record)


		end 
	end


    # method for non-buffered output mode
    def process(tag, es)
      es.each do |time, record|
		$log.debug "GrepRouterLabelOutput.process ", tag, time, record
        # output events to ...
        processRecord(tag, time,record)
      end
    end

    # method for sync buffered output mode
    def write(chunk)
      real_path = extract_placeholders(@path, chunk)

      log.debug "writing data to file", chunk_id: dump_unique_id_hex(chunk.unique_id)

      # for standard chunk format (without #format method)
      chunk.each do |time, record|
        # output events to ...
        processRecord("", time,record)
      end

      ## for custom format (when #format implemented by itself)
      # File.open(real_path, 'w+')

      ## or #write_to(io) is available
      # File.open(real_path, 'w+') do |file|
      #   chunk.write_to(file)
      # end
    end

    # method for async buffered output mode
    def try_write(chunk)
      real_path = extract_placeholders(@path, chunk)

      log.debug "sending data to server", chunk_id: dump_unique_id_hex(chunk.unique_id)

      send_data_to_server(@host, real_path, chunk.read)

      chunk_id = chunk.unique_id

      # create a thread and check whether data is successfully sent or not
      thread_create(:check_send_result) do
        while thread_current_running?
          sleep SENDDATA_CHECK_INTERVAL # == 5

          if check_data_on_server(real_path, chunk_id)
            # commit chunk - chunk will be deleted and not be retried anymore by this call
            commit_write(chunk_id)
            break
          end
        end
      end
    end

    # method for custom format
    def format(tag, time, record)
      [tag, time, record].to_json
    end


	end # class GrepRouterLabelOutput
  end # module Plugin
end # module Fluent
=end