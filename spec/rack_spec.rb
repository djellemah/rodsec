require 'spec_helper'
require 'rodsec/rack'
require 'rack/mock'

RSpec.describe Rodsec::Rack do
  before :all do
    # rspec, shutup already about 'deprecated old syntax'. I've already enabled it.
    if RSpec::Mocks::Syntax.instance_variable_defined? :@warn_about_should
      RSpec::Mocks::Syntax.instance_variable_set :@warn_about_should, false
    end
  end

  def mock_env remote_addr, path = '/'
    Rack::MockRequest.env_for path, 'REMOTE_HOST' => remote_addr
  end

  let(:random_ip) do
    4.times.map{rand 1..254}.join(?.)
  end

  class MockApp
    def status; 200 end

    def headers
      { 'Content-Type' => 'text/plain' }
    end

    def body
      ['cookies']
    end

    def call env
      return status, headers, body
    end
  end

  def mock_rodsec_rack end_app, **options
    # just point rules to a directory with no *.conf files.
    Rodsec::Rack.new end_app, {config: (Pathname __dir__) + 'config', rules: __dir__, **options}
  end

  let :end_app do MockApp.new end
  let :app do mock_rodsec_rack end_app end

  describe 'segfaultiness' do
    it 'survives missing env variables' do
      env = mock_env random_ip
      env.each_key do |key|
        env.delete key unless key =~ /^rack./
      end
      ->{app.call env}.should_not raise_error
    end
  end

  describe 'config' do
    let :app do mock_rodsec_rack end_app, config: @config_dir end

    it 'fails when config directory not found' do
      @config_dir = '/tmp/not_a_real_directory_hopefully'
      ->{app.call mock_env random_ip}.should raise_error(Errno::ENOENT, /No such file or directory.*not_a_real_directory_hopefully/)
    end

    # well, strictly speaking only modsecurity.conf...
    it 'fails when conf files not found' do
      @config_dir = __dir__
      ->{app.call mock_env random_ip}.should raise_error(Errno::ENOENT, /No such file or directory.*conf/)
    end
  end

  describe 'options' do
    let :rodsec_start_regex do /Rodsec::Rack starting/ end

    describe 'default' do
      let :app do mock_rodsec_rack end_app end

      it 'StringIO' do
        app.call mock_env random_ip
        # This is somewhat fragile and will probably need updating
        app.logger.string.should =~ rodsec_start_regex
      end
    end

    describe ':log' do
      let :logger do StringIO.new end
      let :app do mock_rodsec_rack end_app, logger: logger end

      it 'puts' do
        logger.should_receive(:puts).at_least(:once).and_call_original
        app.call mock_env random_ip
        # This is somewhat fragile and will probably need updating
        logger.string.should =~ rodsec_start_regex
      end
    end

    describe ':log_blk' do
      let :strs do [] end
      let :app do mock_rodsec_rack end_app, log_blk: -> tag, str {strs << [tag,str]} end

      it 'calls' do
        app.call mock_env random_ip
        tag, str = strs.first
        tag.should == Rodsec::Rack
        # This is somewhat fragile and will probably need updating
        str.should =~ rodsec_start_regex
      end
    end
  end

  describe 'rack.input rewind' do
    let :local_app do
      Class.new MockApp do
        def call env
          return status, headers, [env['rack.input'].read]
        end
      end.new
    end

    let :text do
      'This is some text you may read at your leisure. In Slippers, smoking a pipe. Watson.'
    end

    let :mock_env do
      input = StringIO.new text
      Rack::MockRequest.env_for '/', 'REMOTE_HOST' => random_ip, input: input
    end

    let :app do mock_rodsec_rack local_app end

    before :each do
      # this is the first call after body exists
      Rodsec::Transaction.any_instance.should_receive(:request_body!).with(text)
    end

    it 'other rack-apps can read it' do
      status, headers, body = app.call mock_env
      body.should == [text]
    end
  end

  describe 'intervention' do
    let :msi do
      msi = Rodsec::Wrapper::ModSecurityIntervention.new Rodsec::Wrapper.msc_new_intervention
      msi.status = 892 # a random number that's definitely not in the http_status ranges
      msi
    end

    describe 'before body exists' do
      before :each do
        Rodsec::Transaction.any_instance.should_receive(:connection!).at_least(:once).and_raise(Rodsec::Intervention, msi)
        end_app.should_not_receive :body
      end

      it 'close body check succeeds when body is nil' do
        ->{app.call mock_env random_ip}.should_not raise_error
      end

      it 'has correct response triple' do
        status, headers, body = app.call mock_env random_ip
        status.should == 892
        body.should == ["Forbidden\n"]
      end
    end

    describe 'after body exists' do
      before :each do
        # this is the first call after body exists
        Rodsec::Transaction.any_instance.should_receive(:response_headers!).and_raise(Rodsec::Intervention, msi)
      end

      it 'closes original body' do
        closeable_body = []
        closeable_body.should_receive(:close)
        end_app.should_receive(:body).and_return closeable_body
        status, headers, body = app.call mock_env random_ip
      end

      describe 'non-closeable body' do
        before :all do
          @saved_false_positives = RSpec::Expectations.configuration.on_potential_false_positives
          RSpec::Expectations.configuration.on_potential_false_positives = :nothing
        end

        after :all do
          RSpec::Expectations.configuration.on_potential_false_positives = @saved_false_positives
        end

        it 'close not called' do
          non_closeable_body = []

          # OK, so the only way to test that the close method is not called, is to
          # make it non-detectable by 'respond_to?' Let the hoop-jumping commence!
          def non_closeable_body.method_missing(meth, *args, &blk)
            if meth == :close
              raise ArgumentError, 'Whew, close call, man!'
            else
              super
            end
          end

          # check that it does in fact raise the error when close is called
          ->{non_closeable_body.close}.should raise_error(ArgumentError, 'Whew, close call, man!')

          # give back non_closeable_body when asked for the body
          end_app.should_receive(:body).and_return non_closeable_body

          # now if the error is not raised, we know close was not called on the body
          ->{app.call mock_env random_ip}.should_not raise_error(ArgumentError, 'Whew, close call, man!')
        end
      end

      it 'has correct response triple' do
        status, headers, body = app.call mock_env random_ip
        status.should == 892
        body.should == ["Forbidden\n"]
      end
    end
  end
end
