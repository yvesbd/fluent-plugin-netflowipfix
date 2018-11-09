lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-netflowipfix"
  spec.version = "1.0.0"
  spec.authors = ["Yves Desharnaus"]
  spec.email   = ["yvesbd@gmail.com"]

  spec.summary       = %q{Fluentd Netflow (v5, v9) and IpFix (v10) Input plugin.}
  spec.description   = %q{Created to replace and add missing functionality to the fluent-plugin-netflow fluentd plugin.}
  spec.homepage      = "https://github.com/yvesbd/fluent-plugin-netflowipfix"
  spec.license       = "Apache-2.0"

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ["lib"]

#  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "test-unit", "~> 3.0"
  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
  spec.add_runtime_dependency "bindata", "~> 2.1"
end
