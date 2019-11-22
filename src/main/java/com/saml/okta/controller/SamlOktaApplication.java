package com.saml.okta.controller;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.saml.okta")
public class SamlOktaApplication {

    public static void main(String[] args) {
        SpringApplication.run(SamlOktaApplication.class, args);
    }
}
