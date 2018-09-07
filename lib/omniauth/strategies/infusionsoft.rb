require 'omniauth-oauth2'
require 'resolv'

module OmniAuth
  module Strategies
    class Infusionsoft < OmniAuth::Strategies::OAuth2
      option :name, 'infusionsoft'

      option :client_options, {
        authorize_url: 'https://signin.infusionsoft.com/app/oauth/authorize',
        token_url:     'https://api.infusionsoft.com/token',
        site:          'https://signin.infusionsoft.com'
      }

      uid{ raw_info['global_user_id'] }

      info do
        {
            :email => raw_info['email'],
        }
      end

      extra do
        {
            'raw_info' => raw_info
        }
      end

      def full_host
        case OmniAuth.config.full_host
          when String
            OmniAuth.config.full_host
          when Proc
            OmniAuth.config.full_host.call(env)
          else
            uri = URI.parse(request.url.gsub(/\?.*$/,''))
            uri.path = ''
            uri.query = nil
            #infusionsoft requires https for callback urls
            #force ssl for all hosts except: 127.x.x.x, fe80:: and ::1
            uri.scheme = 'https' unless Resolv.getaddress(uri.host) =~ /^(fe80::|127|::1)/
            uri.to_s
        end
      end

      def callback_url
        full_host + script_name + callback_path
      end


      def raw_info
        @raw_info ||= access_token.get('https://api.infusionsoft.com/crm/rest/v1/oauth/connect/userinfo').parsed
      end

    end
  end
end
