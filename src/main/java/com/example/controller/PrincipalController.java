package com.example.controller;

import com.example.controller.request.CreateUserDTO;
import com.example.models.ERole;
import com.example.models.RolesEntity;
import com.example.models.UserEntity;
import com.example.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class PrincipalController {

    //6
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/hello")
    public String hello(){
         return "Hello World Not Secured";
     }

     @GetMapping("/helloSecured")
    public String helloSecured(){
        return "Hello World Secured";
     }


     @PostMapping("/createUser")
     public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO){
         System.out.println("aca1");
        Set<RolesEntity> roles = createUserDTO.getRoles().stream()
                .map(role -> RolesEntity.builder()
                        .name(ERole.valueOf(role))
                        .build())
                .collect(Collectors.toSet());
         System.out.println("aca2");
         UserEntity userEntity = UserEntity.builder()
                 .username(createUserDTO.getUsername())
                 .password(passwordEncoder.encode(createUserDTO.getPassword()))
                 .email(createUserDTO.getEmail())
                 .roles(roles)
                 .build();

         userRepository.save(userEntity);
         return ResponseEntity.ok(userEntity);
     }

     @DeleteMapping("/deleteUser")
    public String deleteUser(@RequestParam String id){
        userRepository.deleteById(Long.parseLong(id));
        return "Se ha borrado el user con el id".concat(id);
     }
}
