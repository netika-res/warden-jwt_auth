# frozen_string_literal: true

require 'spec_helper'
require 'rack/test'

shared_examples 'JWT token dispatch' do |path|
  it 'codes a token and adds it to env' do
    post path

    expect(token(last_request)).not_to be_nil
  end

  it 'adds user info to the token' do
    post path

    expect(payload(last_request)['sub']).to eq(user.jwt_subject)
  end

  it 'adds configured client id header into the aud claim' do
    post path

    expect(payload(last_request)['aud']).to eq('warden_tests')
  end

  it 'calls on_jwt_dispatch method in the user' do
    expect(user).to receive(:on_jwt_dispatch)

    post path
  end
end

describe Warden::JWTAuth::Hooks do
  include_context 'configuration'
  include_context 'middleware'
  include_context 'fixtures'

  context 'with user set' do
    let(:app) { warden_app(dummy_app) }

    # :reek:UtilityFunction
    def token(request)
      request.env['warden-jwt_auth.token']
    end

    def payload(request)
      token = token(request)
      Warden::JWTAuth::TokenDecoder.new.call(token)
    end

    context 'when method and path match and scope is known ' do
      before do
        header aud_header.gsub('HTTP_', ''), 'warden_tests'
        login_as user, scope: :user
      end

      include_examples 'JWT token dispatch', '/sign_in'
    end

    context 'when scope is unknown' do
      it 'does nothing' do
        login_as user, scope: :unknown

        post '/sign_in'

        expect(token(last_request)).to be_nil
      end
    end

    context 'when path does not match' do
      it 'does nothing' do
        login_as user, scope: :user

        post '/'

        expect(token(last_request)).to be_nil
      end
    end

    context 'when method does not match' do
      it 'does nothing' do
        login_as user, scope: :user

        get '/sign_in'

        expect(token(last_request)).to be_nil
      end
    end

    context 'when a force_dispatch Proc is provided and returns true, '\
            'and the method or path do not match ' do
      before do
        Warden::JWTAuth.configure do |config|
          config.force_dispatch = proc { |_env| true }
        end
        header aud_header.gsub('HTTP_', ''), 'warden_tests'
        login_as user, scope: :user
      end

      let(:force_dispatch) { config.force_dispatch }

      include_examples 'JWT token dispatch', '/sign_in'
    end

    context 'when a force_dispatch Proc is provided and returns false, '\
            'but the method and path match ' do
      before do
        Warden::JWTAuth.configure do |config|
          config.force_dispatch = proc { |_env| false }
        end
        header aud_header.gsub('HTTP_', ''), 'warden_tests'
        login_as user, scope: :user
      end

      let(:force_dispatch) { config.force_dispatch }

      include_examples 'JWT token dispatch', '/sign_in'
    end

    context 'when a force_dispatch Proc is provided and returns false, '\
            'and the method or path do not match ' do
      before do
        Warden::JWTAuth.configure do |config|
          config.force_dispatch = proc { |_env| false }
        end
        header aud_header.gsub('HTTP_', ''), 'warden_tests'
        login_as user, scope: :user
      end

      let(:force_dispatch) { config.force_dispatch }

      it 'does nothing' do
        get '/'

        expect(token(last_request)).to be_nil
      end
    end
  end
end
