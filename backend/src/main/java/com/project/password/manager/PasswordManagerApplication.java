package com.project.password.manager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class PasswordManagerApplication {

    public static void main(String[] args) {
        
        SpringApplication.run(PasswordManagerApplication.class, args);
    }
}