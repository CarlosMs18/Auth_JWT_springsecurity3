package com.example;

import com.example.models.ERole;
import com.example.models.RolesEntity;
import com.example.models.UserEntity;
import com.example.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserRepository userRepository;
	@Bean
	CommandLineRunner init(){
		return args -> {
			UserEntity userEntity = UserEntity.builder()
					.email("santiago@gmail.com")
					.username("santiago")
					.password(passwordEncoder.encode("1234"))
					.roles(Set.of(RolesEntity.builder().name(ERole.valueOf(ERole.ADMIN.name())).build()))
					.build();

			UserEntity userEntity2 = UserEntity.builder()
					.email("anyio@gmail.com")
					.username("anyi")
					.password(passwordEncoder.encode("1234"))
					.roles(Set.of(RolesEntity.builder().name(ERole.valueOf(ERole.USER.name())).build()))
					.build();

			UserEntity userEntity3 = UserEntity.builder()
					.email("andrea@gmail.com")
					.username("andrea")
					.password(passwordEncoder.encode("1234"))
					.roles(Set.of(RolesEntity.builder().name(ERole.valueOf(ERole.INVITED.name())).build()))
					.build();

			userRepository.save(userEntity);
			userRepository.save(userEntity2);
			userRepository.save(userEntity3);
		};
	}
}
