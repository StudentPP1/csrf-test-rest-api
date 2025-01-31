package github.studentpp1.csrftest.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestController {

    @PostMapping("/protected")
    public ResponseEntity<String> protectedEndpoint(@RequestBody Map<String, String> body) {
        return ResponseEntity.ok("Received: " + body.get("data"));
    }
}
