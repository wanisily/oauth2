package com.wanisily.config;

import com.wanisily.domain.OAuthUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.annotation.Resource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 使用jwt来承载token  ,jwt是无状态的，可以通过playload来存放用户相关的信息
 */
@EnableAuthorizationServer
@Configuration
public class JwtAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private static final String CLIENT_ID = "client_id_1";
    private static final String CLIENT_SECRET = new BCryptPasswordEncoder().encode("123456");

    @Resource
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
            // 开启/oauth/token_key验证端口无权限访问
            .tokenKeyAccess("permitAll()")
            // 开启/oauth/check_token验证端口认证权限访问
            .checkTokenAccess("isAuthenticated()")
            .allowFormAuthenticationForClients();// 允许客户端进行表单认证,这样通过post的表单请求 /oauth/token
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient(CLIENT_ID)
                .secret(CLIENT_SECRET)
                //支持哪种授权模式
                .authorizedGrantTypes("password", "authorization_code", "implicit", "client_credentials", "refresh_token")
                //权限
                .scopes("read", "write")
                .accessTokenValiditySeconds(3600) // token失效时间
                .refreshTokenValiditySeconds(864000) //refresh token失效时间
                .redirectUris("https://www.baidu.com/");
//                .autoApprove("read");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();// 增强器链
        List<TokenEnhancer> tokenEnhancerList = new ArrayList<>();//增强器
        tokenEnhancerList.add(tokenEnhancer());//在jwt中存放定义的数据
        tokenEnhancerList.add(jwtAccessTokenConverter());//定义jwt的公钥，私钥密钥
        tokenEnhancerChain.setTokenEnhancers(tokenEnhancerList);

        endpoints.authenticationManager(authenticationManager) //设置认证管理， 这个使用springSecurity容器的
                .accessTokenConverter(jwtAccessTokenConverter())//设置jwt的公私钥
                .tokenEnhancer(tokenEnhancerChain)// 设置增强器
                .userDetailsService(userDetailsService) // 设置认证用户名，密码的方式
                // refresh token有两种使用方式：重复使用(true)、非重复使用(false)，默认为true
                //1 重复使用：access token过期刷新时， refresh token过期时间未改变，仍以初次生成的时间为准
                //2 非重复使用：access token过期刷新时， refresh token过期时间延续，在refresh token有效期内刷新便永不失效达到无需再次登录的目的
                .reuseRefreshTokens(true).allowedTokenEndpointRequestMethods(HttpMethod.GET,HttpMethod.POST);
    }

    /**
     * JWT内容增强, 这里面可以存放自己额外的内容
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (accessToken, authentication) -> {
            //我们附加在token中的条件
            Map<String, Object> additionalInfo = new HashMap<>();
            OAuthUserDetails user = (OAuthUserDetails) authentication.getPrincipal();
            additionalInfo.put("userId", user.getId());
            additionalInfo.put("username", user.getUsername());
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
            return accessToken;
        };
    }

    /**
     * 对jwt进行加密
     *
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyPair());  //设置非对应加密密钥对
//        converter.setSigningKey("123"); //设置对称加密的密钥
        return converter;
    }

    /**
     * 从classpath下的密钥库中获取密钥对（公钥+私钥），密钥对的意思
     *
     * @return
     */
    @Bean
    public KeyPair keyPair() {
        KeyStoreKeyFactory factory = new KeyStoreKeyFactory(new ClassPathResource("wanxing.jks"), "123456".toCharArray());
        return factory.getKeyPair("wanxing","123456".toCharArray());
    }
}
