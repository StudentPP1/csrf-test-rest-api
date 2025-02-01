package github.studentpp1.csrftest.auth.utils;

import github.studentpp1.csrftest.model.UserEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;

public final class SecurityUtils {
    private static final Logger logger = LoggerFactory.getLogger(SecurityUtils.class);
    public static UserEntity getAuthenticatedUser() {
        // достаем из контекста нашего пользователя и приводим к нужному типу
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserEntity user) {
            return user;
        }
        else {
            logger.error("User requested but not found in SecurityContextHolder");
            throw new RuntimeException("Authentication required");
        }
    }
}
