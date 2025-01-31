package github.studentpp1.csrftest.service;

import github.studentpp1.csrftest.model.UserEntity;
import github.studentpp1.csrftest.repository.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserEntity getUserEntity(final String username) {
        Optional<UserEntity> user = userRepository.findByUsername(username);
        return user.orElseThrow(
                () -> new UsernameNotFoundException("User with username: " + username + " doesn't exist")
        );
    }

    public UserEntity saveUser(UserEntity user) {
        return userRepository.save(user);
    }
}
