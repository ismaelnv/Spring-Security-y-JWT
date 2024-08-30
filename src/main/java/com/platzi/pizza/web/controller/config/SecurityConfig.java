package com.platzi.pizza.web.controller.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
//Definir que tipo de decorador de seguridad estamos usando y activarlo
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity htpp) throws Exception {

        htpp
                .csrf().disable()
                .cors().and() // activa los cors
                .authorizeHttpRequests() //para protejer todas las peticiones http
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/customers/**").hasAnyRole("ADMIN", "CUSTOMER")
                .requestMatchers(HttpMethod.GET, "/api/pizzas/**").hasAnyRole("ADMIN", "CUSTOMER", "COCINERO") //para darle permisos
                .requestMatchers(HttpMethod.GET, "/api/pizzas/**").hasRole("ADMIN") //para darle permisos
                .requestMatchers(HttpMethod.GET, "/api/customers/**").hasRole("COCINERO") //para darle permisos
                .requestMatchers(HttpMethod.GET,"/api/orders").hasAuthority("random_cocinero")
                .requestMatchers(HttpMethod.PUT).hasRole("ADMIN") //solo permite usar el metodo put a los ADMIN
                .requestMatchers("/api/orders/random").hasAuthority("random_order")
                .requestMatchers("/api/orders/**").hasRole("ADMIN") //No esta permitido usar el metodo put
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

        return  htpp.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return  configuration.getAuthenticationManager();
    }


    @Bean
    public PasswordEncoder passwordEncoder(){

        return new BCryptPasswordEncoder();
    }

}
