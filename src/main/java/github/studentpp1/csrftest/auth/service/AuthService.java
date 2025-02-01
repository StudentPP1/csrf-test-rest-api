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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    public AuthService(
            final UserService userService,
            final PasswordEncoder passwordEncoder,
            final AuthenticationManager authenticationManager
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public void logout(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        logger.info("{}={}", token.getHeaderName(), token.getToken());

        SecurityContextHolder.clearContext(); // Очищення контексту безпеки

        HttpSession session = request.getSession(); // Отримуємо сесію
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
        authenticateUserAndSendSession(
                request,
                response,
                userLoginRequest.getUsername(),
                userLoginRequest.getPassword()
        );
    }

    public void register(
            RegisterRequest userRegisterRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        logger.info("{}={}", token.getHeaderName(), token.getToken());

        final String username = userRegisterRequest.getUsername();
        final String password = userRegisterRequest.getPassword();

        if (!this.isUserAuthenticated() && !this.isUserExists(username, password)) {
            // create & save user
            UserEntity user = new UserEntity();
            user.setName(userRegisterRequest.getName());
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(password));
            user = userService.saveUser(user);

            // save user to application's context
            saveUserToContext(user);

            //  set session cookie in response
            authenticateUserAndSendSession(
                    request,
                    response,
                    username,
                    password
            );
        } else {
            throw new AuthenticationException("user already registered");
        }
    }

    private boolean isUserAuthenticated() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UserEntity;
    }

    private boolean isUserExists(final String username, final String password) {
        try {
            UserEntity user = userService.getUserEntity(username);
            return passwordEncoder.matches(password, user.getPassword());
        } catch (final UsernameNotFoundException exception) {
            return false;
        }
    }

    private void saveUserToContext(UserEntity user) {
        // помещаем нового пользователя в контекст приложения напрямую
        logger.info("Context: " + SecurityContextHolder.getContext());
        logger.info("start authentication");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                user,
                user.getPassword(),
                user.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        logger.info("end authentication");
    }

    private void authenticateUserAndSendSession(
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
        /*
        в .authenticate() методе достаем нашего пользователя
        из хранилища (по username который передали в UsernamePasswordAuthenticationToken)
        через провайдера (в нашем случае DaoAuthenticationProvider)
        и проверяем хэшированный пароль с тем который передали в UsernamePasswordAuthenticationToken
        */
        Authentication authentication = authenticationManager.authenticate(token);
        /*
        SecurityContextHolder -> wrapper над контекстом (со статическими методами получения контекста)
        */
        SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();
        // получаем контекст приложения
        SecurityContext context = holder.getContext();
        logger.info("set authentication");
        context.setAuthentication(authentication);
        // помещаем наш объект Authentication (похож на UserDetails) в контекст приложения
        holder.setContext(context);
        logger.info("saving context");
        /*
        сохраняем контекст в репозитории (в нашем случае HttpSessionSecurityContextRepository ->
        сохраняем в сессии, которая будет записана в объекте HttpServletResponse)
        */
        contextRepository.saveContext(context, request, response);
        logger.info("end creating session");
    }
}