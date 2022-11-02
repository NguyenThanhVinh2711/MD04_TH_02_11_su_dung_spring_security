package com.codegym.security;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //Cấu hình xác thực user , admin
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}12345").roles("USER")
                .and().withUser("admin").password("{noop}12345").roles("ADMIN");
    }

    //Cấu hình phân quyền
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .and()
                // URL được bảo mật chỉ user mới được vào
                .authorizeRequests().antMatchers("/user**").hasRole("USER")
                .and()
                // URL được bảo mật chỉ admin mới được vào
                .authorizeRequests().antMatchers("/admin**").hasRole("ADMIN")
                .and()
                //form đăng nhập
                .formLogin()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }

}
