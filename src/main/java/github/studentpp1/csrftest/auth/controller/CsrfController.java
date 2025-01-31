package github.studentpp1.csrftest.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class CsrfController {
    private final Logger logger = LoggerFactory.getLogger(CsrfController.class);

    @GetMapping("/csrf-token")
    public CsrfToken getCsrfToken(HttpServletRequest request) {
        logger.warn("CSRF: getting request...");
        CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
        if (csrfToken == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "CSRF Token not found");
        }
        logger.warn("CSRF: sending token...");
        return csrfToken;
    }
}
