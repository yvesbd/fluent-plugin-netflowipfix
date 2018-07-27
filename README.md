# Netflow(v5/v9) and IPfix(v10) plugin for Fluentd
# fluent-plugin-netflowipfix

[Fluentd](https://fluentd.org/) input plugin that acts as Netflow v5/v9 and IPfix (v10) collector.


## Installation

### RubyGems

```
$ gem install fluent-plugin-netflowipfix
```

### Bundler

Add following line to your Gemfile:

```ruby
gem "fluent-plugin-netflowipfix"
```

And then execute:

```
$ bundle
```

## Configuration


    <source>
      type netflowipfix
      tag netflow.event

      # optional parameters
      bind 192.168.0.1
      port 2055
      cache_ttl 6000
      definitions /path/to/custom_fields.yaml
    </source>

**bind**

IP address on which the plugin will accept Netflow.  
(Default: '0.0.0.0')

**port**

UDP port number on which tpe plugin will accept Netflow.  
(Default: 5140)

**cache_ttl**

Template cache TTL for Netflow v9 or IPfix v10 in seconds. Templates not refreshed from the Netflow v9 exporter within the TTL are expired at the plugin.  
(Default: 4000)

**switched_times_from_uptime**

When set to true, the plugin stores system uptime for ```first_switched``` and ```last_switched``` instead of ISO8601-formatted absolute time.  
(Defaults: false)
TODO: This is currently disabled

**definitions**

YAML file containing Netflow field definitions to overfide pre-defined templates. Example is like below

    ---
    4:          # field value
    - :uint8    # field length
    - :protocol # field type

## Pending

* Tests
* A few TODOs in the code

## Copyright

* Copyright(c) 2018- Yves Desharnais
* License
  * Apache License, Version 2.0

