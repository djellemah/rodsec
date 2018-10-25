require 'yaml'

require 'spec_helper'
require 'rodsec/transaction'

include Rodsec

RSpec.describe Transaction do
  let :log_blk do
    lambda do |str| puts str end
  end

  let :msc do Modsec.new &log_blk end
  let :rule_set do
    config_dir = Pathname(__dir__) + 'config'
    rules_dir = __dir__
    ReadConfig.read_config config_dir, rules_dir, &log_blk
  end

  subject do described_class.new msc, rule_set end

  # epsilon, the empty string https://en.wikipedia.org/wiki/Empty_string#Formal_theory
  Ɛ = String.new.freeze
  let :εhash do {Ɛ => Ɛ} end
  let :nilhash do {nil => nil} end

  describe 'not segfault on nils and other bad input' do
    it 'connection!' do
      ->{subject.connection! nil, 0, nil, 0}.should_not raise_error
      ->{subject.connection! nil, nil, nil, nil}.should raise_error(TypeError, /Integer/)
      ->{subject.connection! nil, 0, nil, nil}.should raise_error(TypeError, /Integer/)

      ->{subject.connection! Ɛ, 0, Ɛ, 0}.should_not raise_error
      ->{subject.connection! Ɛ, Ɛ, Ɛ, Ɛ}.should raise_error(ArgumentError, /Integer/)
      ->{subject.connection! Ɛ, 0, Ɛ, Ɛ}.should raise_error(ArgumentError, /Integer/)
    end

    it 'uri!' do
      ->{subject.uri! nil, nil, nil}.should_not raise_error
      ->{subject.uri! Ɛ, Ɛ, Ɛ}.should_not raise_error
    end

    it 'request_headers!' do
      ->{subject.request_headers! nil}.should raise_error(NoMethodError, /each_with_object/)
      ->{subject.request_headers! Hash.new}.should_not raise_error
      ->{subject.request_headers! nilhash}.should_not raise_error
      ->{subject.request_headers! εhash}.should_not raise_error
    end

    it 'request_body!' do
      ->{subject.request_body! nil}.should_not raise_error
      ->{subject.request_body! Ɛ}.should_not raise_error
    end

    it 'response_headers!' do
      ->{subject.response_headers! 0, nil, Hash.new}.should_not raise_error
      ->{subject.response_headers! 0, nil, nil}.should raise_error(NoMethodError, /each_with_object/)
      ->{subject.response_headers! nil, nil, Hash.new}.should raise_error(TypeError, /Integer/)

      ->{subject.response_headers! 0, Ɛ, Hash.new}.should_not raise_error
      ->{subject.response_headers! 0, Ɛ, εhash}.should_not raise_error
      ->{subject.response_headers! 0, Ɛ, nilhash}.should_not raise_error
      ->{subject.response_headers! 0, Ɛ, Ɛ}.should raise_error(NoMethodError, /each_with_object/)
      ->{subject.response_headers! Ɛ, Ɛ, Hash.new}.should raise_error(ArgumentError, /Integer/)
    end

    it 'response_body!' do
      ->{subject.response_body! nil}.should_not raise_error
      ->{subject.response_body! Ɛ}.should_not raise_error
    end
  end

  describe '#enum_of_body' do
    # protected method, so use send

    it 'handles nil' do
      subject.send(:enum_of_body, nil).should == ['']
    end

    it 'handles String' do
      subject.send(:enum_of_body, 'This is a single stringle').should == ['This is a single stringle']
    end

    it 'handles Enumerable' do
      body_parts = YAML.load <<-EOY
        - On the first day, everyone was optimistic.
        - On the second day they were cheerful.
        - By the third day they were running out of water and becoming anxious.
        - On the fourth day, the horror-movie villain appeared out of the mist.
      EOY
      subject.send(:enum_of_body, body_parts).should == body_parts
    end
  end

  describe '#truncate_inspect' do
    it 'inspects shortish string' do
      subject.send(:truncate_inspect, "hello there").should == %q("hello there")
    end

    it 'truncates longish string' do
      long = '=' * 400
      subject.send(:truncate_inspect, long).should == %Q("#{'=' * 120}")
    end

    it 'inspects other objects' do
      subject.send(:truncate_inspect, [8,1,9,2]).should == "[8, 1, 9, 2]"
    end
  end
end
