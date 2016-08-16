require 'omniauth-oauth2'
require 'net/http'
require 'net/https'
require 'nokogiri'

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
            #infusionsoft requires https for callback urls. Support HTTP for localhost
            uri.scheme = 'https' unless uri.host.match(/\Alocalhost\Z/i)
            uri.to_s
        end
      end

      uid { "#{user_info['globalUserId']}-#{user_info['appAlias']}" }

      info do
        {
          name: user_info['displayName'],
          email: user_info['casUsername']
        }
      end

      def user_info
        @user_info ||= get_user_info(access_token.token)
      end

      def get_user_info(token)
        uri = URI.parse("https://api.infusionsoft.com/crm/xmlrpc/v1?access_token=#{token}")
        https = Net::HTTP.new(uri.host, uri.port)
        https.use_ssl = true
        req = Net::HTTP::Post.new(uri.request_uri, {'Content-Type' =>'application/xml'})
        req.body = %q{<?xml version='1.0' encoding='UTF-8'?>
<methodCall>
  <methodName>DataService.getUserInfo</methodName>
  <params></params>
</methodCall>}

        res = https.request(req)
        return {} unless res.code == "200"

        reply = Nokogiri::XML(res.body)
        return {} unless reply.xpath('//fault').size == 0

        data_hash = {}
        reply.xpath('//member').each do |member|
          children = member.children.select(&:element?)
          name = children[0].text()
          value = children[1].text()
          data_hash[name] = value
        end
        data_hash
      end
    end
  end
end
