require "helper"
require "fluent/plugin/in_netflowipfix.rb"

class NetflowipfixInputTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  test "failure" do
    flunk
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::NetflowipfixInput).configure(conf)
  end
end
