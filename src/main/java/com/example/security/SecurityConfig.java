package com.example.security;

import com.example.security.filters.JwtAuthenticationFilter;
import com.example.security.filters.JwtAuthorizationFilter;
import com.example.security.jwt.JwtUtils;
import com.example.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//1
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) //final habilitar las anotaciones de spring securitt
public class SecurityConfig {

    //21
    @Autowired
    JwtUtils jwtUtils;

    //19
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    //26
    @Autowired
    JwtAuthorizationFilter authorizationFilter;

    //2
    @Bean //22 colocar como arguemnto de entrada  AuthenticationManager authenticationManager
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, AuthenticationManager authenticationManager) throws Exception {

        //20
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtUtils);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager); //por defecto la ruta para ingresar es /login
        jwtAuthenticationFilter.setFilterProcessesUrl("/login"); // si queremso cambia la ruta url por defecto

        /* fin 20 */
        return httpSecurity.
                csrf(config -> config.disable())
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/hello").permitAll();
                    //auth.requestMatchers("/accessAdmin").hasAnyRole("ADMIN","USER");
                    auth.anyRequest().authenticated();
                })
                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                //22
                .addFilter(jwtAuthenticationFilter)

                /* fin 22 */

                //27
                .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }

    //3 debe de ser utilizado o administrado por un objetoque administre la autentiacion para eos es el autenticacionManager

    /*

      @Bean
    UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager  = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("santiago")
                .password("1234")
                        .roles()
                .build());
        return manager;
    }
     */




    //5
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //4 OBJETO QUE SE ENCARGA DE LA AUTENTICACION DE LOS USUARIOS, a su vez requiere un password encoder para manejar de manera optima
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity,PasswordEncoder passwordEncoder) throws Exception {
        return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService) //pasamos el usuarios que nosotros vamos a autenticar
                .passwordEncoder(passwordEncoder)
                .and().build();


    }

    //23
   /*
    public static void main(String[] args){
        System.out.println(new BCryptPasswordEncoder().encode(""));
    }
    */
}
