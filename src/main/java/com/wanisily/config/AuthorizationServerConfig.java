package com.wanisily.config;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.annotation.Resource;
import java.util.Arrays;

/**
 * 测试oauth2的认证，授权，授权码模式、密码模式等  ,使用redis来存储 token
 */
/*@EnableAuthorizationServer
@Configuration*/
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private static final String RESOURCE_ID = "oauth-resource";
    private static final String CLIENT_ID = "client_id_1";
    private static final String CLIENT_SECRET = new BCryptPasswordEncoder().encode("123456");

    @Resource
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    @SneakyThrows
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer
            // 开启/oauth/token_key验证端口无权限访问
            .tokenKeyAccess("permitAll()")
            // 开启/oauth/check_token验证端口认证权限访问
            .checkTokenAccess("isAuthenticated()")
            .allowFormAuthenticationForClients();// 允许客户端进行表单认证,这样通过post的表单请求 /oauth/token


//        oauthServer.addTokenEndpointAuthenticationFilter(new CorsFilter(corsConfigurationSource()));
    }

    @Override
    @SneakyThrows
    public void configure(ClientDetailsServiceConfigurer clients) {
        clients.inMemory()
                .withClient(CLIENT_ID)
                .secret(CLIENT_SECRET)
                //oauth2的几种授权模式，
                //password:密码模式(需要client_Id，client_secret，username,password)
                //authorization_code:授权码模式(最安全，但是繁琐，适用场景，微信，qq授权登录，获取头像信息)
                //implicit：简单模式
                //client_credentials：客户端模式（只需要client_Id，client_secret）
                .authorizedGrantTypes( "password","authorization_code", "implicit", "client_credentials", "refresh_token")
                //返回权限
                .scopes("user_info")  //乱写的权限，需要手动点击获取授权码,会弹出让你授权user_info, 这里token放在redis内存中了，授权后可能就会弹出让你授权的弹窗
//                .autoApprove(true)//自动授权，在授权码模式的时候，不用动手点击授权码
                .scopes("read", "write") // 授权读写权限后,会弹出让你授权 read ,write, 这里token放在redis内存中了，授权后可能就会弹出让你授权的弹窗
//                .autoApprove("read")
                .accessTokenValiditySeconds(3600) // token失效时间
                .refreshTokenValiditySeconds(864000) //refresh token失效时间
                .redirectUris("https://www.baidu.com/"); /// authorization_code 的回调url地址
    }

    @Override
    @SneakyThrows
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.userDetailsService(userDetailsService)
                .authenticationManager(authenticationManager)
                .tokenStore(tokenStore()) //使用redis来承载token
                //接收GET和POST
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
    }





    /**
     *  处理跨域问题
     * @return
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "HEAD", "DELETE", "OPTION"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.addExposedHeader("Authorization");
        configuration.addExposedHeader("Content-disposition");//文件下载消息头
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }



    @Bean
    public TokenStore tokenStore(){
        RedisTokenStore tokenStore = new RedisTokenStore(redisConnectionFactory);
        tokenStore.setPrefix("auth-token:");
        return tokenStore;
    }
}
