package com.capstone.shop;

import com.capstone.shop.entity.Role;
import com.capstone.shop.entity.User;
import com.capstone.shop.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CapstoneApplication implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    public static void main(String[] args) {
        SpringApplication.run(CapstoneApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        User admin = userRepository.findByRole(Role.ROLE_ADMIN);
        if (admin == null) {
            User user = new User();
            user.setName("Admin");
            user.setEmail("admin@gmail.com");
            user.setRole(Role.ROLE_ADMIN);
            user.setPassword("admin");
            userRepository.save(user);
        }
    }
}
