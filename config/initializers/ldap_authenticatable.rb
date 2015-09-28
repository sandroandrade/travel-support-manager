require 'net/ldap'
require 'devise/strategies/authenticatable'
require 'string_extension'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable
      def authenticate!
        if params[:user]
          ldap = Net::LDAP.new
          ldap.host = '10.1.0.4'
          ldap.port = 389
          ldap.base = 'DC=intranet,DC=cefetba,DC=br'
          ldap.auth email, password
          exclude_titleize = %w(dos da de)

          if ldap.bind
            user = User.find_or_create_by(email: email)
            login = email.split(/@/).first
            userentry = ldap.search(:filter => "sAMAccountName=#{login}").first
            user.first_name = userentry[:givenname][0].to_s.titleize(exclude: exclude_titleize)
            user.last_name = userentry[:sn][0].to_s.titleize(exclude: exclude_titleize)
            success!(user)
          else
            fail(:invalid_login)
          end
        end
      end

      def email
        params[:user][:email].include?("@") ? params[:user][:email]:params[:user][:email] + "@ifba.edu.br"
      end

      def password
        params[:user][:password]
      end

    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)
