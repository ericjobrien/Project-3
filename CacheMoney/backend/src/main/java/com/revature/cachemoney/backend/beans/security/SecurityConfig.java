package com.revature.cachemoney.backend.beans.security;

import com.revature.cachemoney.backend.beans.customAuthentication.CustomAuthenticationDetailsSource;
import com.revature.cachemoney.backend.beans.customAuthentication.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Spring Security configuration file to set up request authentication.
 * 
 * @author Ibrahima Diallo, Brian Gardner, Cody Gonsowski, & Jeffrey Lor
 */
@Configuration // TODO: trying 2fa
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //TODO: trying 2fa
    @Autowired
    private CustomAuthenticationDetailsSource customAuthenticationDetailsSource;

    /**
     * Create a new BCryptPasswordEncoder for storing passwords in the database.
     * 
     * @return new BCryptPasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //TODO: trying 2fa
    @Bean
    public DaoAuthenticationProvider authenticationProvider(@Autowired UserDetailsService userDetailsService,
                                                            @Autowired PasswordEncoder passwordEncoder) {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    /**
     * Configures user & admin roles for accessing the application.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth
                .inMemoryAuthentication()
                .withUser("user")
                .password(encoder.encode("password"))
                .roles("USER");
    }

    /**
     * Requests must be authorized in order to go through.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // enable CORS & disable CSRF
        http = http.cors().and().csrf().disable();

        // stateless session management
        http = http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and();
    }

    /**
     * CORS filter that works with Spring Security.
     * 
     * @return CorsConfigurationSource
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());

        return source;
    }
}
