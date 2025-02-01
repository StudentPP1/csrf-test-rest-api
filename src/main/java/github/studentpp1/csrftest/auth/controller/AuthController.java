package github.studentpp1.csrftest.auth.controller;

import github.studentpp1.csrftest.auth.service.AuthService;
import github.studentpp1.csrftest.request.LoginRequest;
import github.studentpp1.csrftest.request.RegisterRequest;
import github.studentpp1.csrftest.response.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/getSession")
    @ResponseBody
    public UserResponse getSession() {
        return authService.getSession();
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        authService.logout(request);
        return ResponseEntity.status(200).body("Success logout");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        authService.login(loginRequest, request, response);
        return ResponseEntity.status(200).body("Success login");
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody RegisterRequest registerRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        authService.register(registerRequest, request, response);
        return ResponseEntity.status(200).body("Success register");
    }
}
