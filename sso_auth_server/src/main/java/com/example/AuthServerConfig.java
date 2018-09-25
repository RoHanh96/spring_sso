package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	 @Override
	    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
	        oauthServer.tokenKeyAccess("permitAll()")
	            .checkTokenAccess("isAuthenticated()");
	        oauthServer.allowFormAuthenticationForClients();
	    }

	    @Override
	    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
	        clients.inMemory()
	            .withClient("SampleClientId")
	            .secret(passwordEncoder.encode("secret"))
	            .authorizedGrantTypes("authorization_code")
	            .scopes("user_info")
	            .autoApprove(true)
	            .redirectUris("http://localhost:8083/ui/login","http://localhost:8084/ui2/login","http://localhost:8083/login")
	        // .accessTokenValiditySeconds(3600)
	        ; // 1 hour
	    }
}
