package com.wanisily.config;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.annotation.Resource;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //只允许登录请求,  这里没有设置oauth2的url，是通过 @link com.wanisily.config.AuthorizationServerConfig configure
        http.authorizeRequests().antMatchers("/login,/getPublicKey").permitAll()
                .anyRequest().authenticated()
                .and().formLogin().permitAll()  // 这个是允许访问登录页面，如果没有登录，请求其他页面，就会跳转到登录页面， myLogin是自定义的登录请求的url
//                .and().formLogin().loginPage("/myLogin").permitAll()  // 这个是允许访问登录页面，如果没有登录，请求其他页面，就会跳转到登录页面， myLogin是自定义的登录请求的url
                .and().csrf().disable();
    }

    /**
     * 创建authenticationManager bean
     * 方法名称写成authenticationManager 密码模式请求token会报错
     *
     * @return
     */
    @Override
    @Bean
    @SneakyThrows
    public AuthenticationManager authenticationManagerBean() {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
