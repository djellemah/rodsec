require "spec_helper"

RSpec.describe Rodsec do
  it "has a version number" do
    Rodsec::VERSION.should_not be_nil
  end
end
