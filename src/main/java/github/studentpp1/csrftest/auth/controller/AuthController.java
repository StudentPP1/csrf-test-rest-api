package github.studentpp1.csrftest.auth.controller;

import github.studentpp1.csrftest.auth.service.AuthService;
import github.studentpp1.csrftest.request.LoginRequest;
import github.studentpp1.csrftest.request.RegisterRequest;
import github.studentpp1.csrftest.response.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/getSession")
    public UserResponse getSession() {
        return authService.getSession();
    }

    @PostMapping("/login")
    public void login(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        authService.login(loginRequest, request, response);
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody RegisterRequest registerRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        authService.register(registerRequest, request, response);
        return ResponseEntity.status(200).body("Success");
    }
}
