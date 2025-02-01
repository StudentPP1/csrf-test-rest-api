package github.studentpp1.csrftest.auth.service;

import github.studentpp1.csrftest.auth.utils.SecurityUtils;
import github.studentpp1.csrftest.model.UserEntity;
import github.studentpp1.csrftest.request.LoginRequest;
import github.studentpp1.csrftest.request.RegisterRequest;
import github.studentpp1.csrftest.response.UserResponse;
import github.studentpp1.csrftest.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;

@Service
public class AuthService {
    private final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();

    public AuthService(UserService userService, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public void logout(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        logger.info("{}={}", token.getHeaderName(), token.getToken());

        SecurityContextHolder.clearContext(); // Очищення контексту безпеки

        HttpSession session = request.getSession(false); // Отримуємо сесію (якщо є)
        if (session != null) {
            session.invalidate(); // Завершуємо сесію
        }

        logger.info("User logged out successfully");
    }

    public UserResponse getSession() {
        UserEntity user = SecurityUtils.getAuthenticatedUser();
        logger.info("Get user: " + user);
        return UserResponse.builder()
                .name(user.getName())
                .username(user.getUsername())
                .build();
    }

    public void login(LoginRequest userLoginRequest,
                      HttpServletRequest request,
                      HttpServletResponse response
    ) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        logger.info("{}={}", token.getHeaderName(), token.getToken());

        // set session cookie in response
        try {
            createSession(
                    request,
                    response,
                    userLoginRequest.getUsername(),
                    userLoginRequest.getPassword()
            );
        } catch (Exception exception) {
            throw new RuntimeException("User not found");
        }
    }

    public void register(
            RegisterRequest userRegisterRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        logger.info("{}={}", token.getHeaderName(), token.getToken());

        UserEntity user = new UserEntity();
        user.setName(userRegisterRequest.getName());
        user.setUsername(userRegisterRequest.getUsername());
        user.setPassword(passwordEncoder.encode(userRegisterRequest.getPassword()));
        user = userService.saveUser(user);

        // save user to context
        authenticateUser(user);

        //  set session cookie in response
        createSession(
                request,
                response,
                userRegisterRequest.getUsername(),
                userRegisterRequest.getPassword()
        );
    }

    private boolean isAuthenticated() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UserEntity;
    }

    private void authenticateUser(UserEntity user) throws AuthenticationException {
        logger.info("Context: " + SecurityContextHolder.getContext());

        if (!isAuthenticated()) {
            logger.info("start authentication");
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    user,
                    user.getPassword(),
                    user.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            logger.info("end authentication");
        }
        else {
            throw new AuthenticationException("user already registered");
        }
    }

    private void createSession(
            HttpServletRequest request,
            HttpServletResponse response,
            String username,
            String password
    ) {
        logger.info("start creating session");
        var token = UsernamePasswordAuthenticationToken.unauthenticated(
                username,
                password
        );
        Authentication authentication = authenticationManager.authenticate(token);
        SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();
        SecurityContext context = holder.getContext();
        logger.info("set authentication");
        context.setAuthentication(authentication);
        holder.setContext(context);
        logger.info("saving context");
        contextRepository.saveContext(context, request, response);
        logger.info("end creating session");
    }
}