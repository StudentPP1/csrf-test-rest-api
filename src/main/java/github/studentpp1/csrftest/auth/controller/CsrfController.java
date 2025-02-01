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

    /*
    Для GET не нужен CSRF-token
    Для POST, PUT, DELETE, PATCH нужен CSRF-token (когда пользуемся сессиями, для безопасности данных,
    что б нельзя было подделать запрос злоумышленнику и получить данные с сервера)

    Spring отсылает CSRF-token в cookie, но что бы их получить, делаем запрос на выдачу токена и тогда нам
    одновременно приходит CSRF-token в cookie и тот же самый CSRF-token в JSON ответе, который далее мы помещаем в Header.
    (Также можем отправлять пустой ResponseEntity.ok() в GET запросе и на фронт-енд доставать CSRF-token из cookie)

    В CsrfFilter будет проверка на соответствие нашего CSRF-token, который мы получили от сервера (в Cookie)
    и тот, который мы прислали (в Header).
    */
    @GetMapping("/csrf-token")
    public CsrfToken getCsrfToken(HttpServletRequest request) {
        logger.info("CSRF: getting request...");
        // get CSRF-token from cookie in Headers
        CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
        if (csrfToken == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "CSRF Token not found");
        }
        logger.info("CSRF: sending token...");
        return csrfToken; // send CSRF-token
    }
}
