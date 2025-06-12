package com.sb02.practice.security.config;

import com.sb02.practice.security.entity.Role;
import com.sb02.practice.security.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserService userService;

    public DataInitializer(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void run(String... args) throws Exception {
        // 테스트용 사용자 생성
        try {
            userService.createUser("admin", "password", "admin@example.com", Role.ADMIN);
            userService.createUser("user", "password", "user@example.com", Role.USER);
            userService.createUser("manager", "password", "manager@example.com", Role.MANAGER);

            System.out.println("=".repeat(50));
            System.out.println("테스트 사용자 데이터 초기화 완료");
            System.out.println("- admin/password (ADMIN 권한)");
            System.out.println("- user/password (USER 권한)");
            System.out.println("- manager/password (MANAGER 권한)");
            System.out.println("=".repeat(50));

        } catch (Exception e) {
            System.err.println("테스트 데이터 초기화 중 오류 발생: " + e.getMessage());
        }
    }
}