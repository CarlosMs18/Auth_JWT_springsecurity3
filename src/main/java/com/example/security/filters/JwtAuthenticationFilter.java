package com.example.security.filters;

import com.example.models.UserEntity;
import com.example.security.jwt.JwtUtils;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

//11
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    //14

    private JwtUtils jwtUtils;

    //15
    public JwtAuthenticationFilter(JwtUtils jwtUtils){
        this.jwtUtils = jwtUtils;
    }

    //12 Intentar autenticarse
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UserEntity userEntity = null;
        String username = "";
        String password = "";
        try{

            //Recuperar el usuario
            //mapear de un json a objetos java mediante libreria jackson
            userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
            username = userEntity.getUsername();
            password = userEntity.getPassword();
        } catch (StreamReadException e) {
            throw new RuntimeException(e);
        } catch (DatabindException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //Con el cual nos vamos a autenticar en la aplicacion
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        return getAuthenticationManager().authenticate(authenticationToken);

    }


    //13 Cuando se autenticado correctamente que haremos
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        //Necesitamos obtener los detalles del usuario
        User user = (User) authResult.getPrincipal(); // obtenemos todos los detalles que tiene el usuario

        //16
        String token = jwtUtils.generarAccesToken(user.getUsername());

        response.addHeader("Authorization",token);

        Map<String , Object> httpResponse  = new HashMap<>();//Mapeamos la rpta con este hash
        httpResponse.put("token",token);
        httpResponse.put("Message","Authentication correcta");
        httpResponse.put("Username",user.getUsername());

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush(); //con esto nos estamosasegurando de que todo se escriba correctamente


        super.successfulAuthentication(request, response, chain, authResult);
    }
}
