package com.endlessshw.webattacker_agent;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class WebAttackerAgentApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebAttackerAgentApplication.class, args);
    }

}
