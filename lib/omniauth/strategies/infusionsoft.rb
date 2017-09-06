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
    end
  end
end
