package com.example.demo.appuser;

import com.example.demo.registration.token.ConfirmationToken;
import com.example.demo.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import net.bytebuddy.asm.Advice;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {
    private final static String USER_NOT_FOUND_MSG =
            "User with email %s not found!";
    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }
    public String signUpUser(AppUser appUser) {
        Optional<AppUser> user = appUserRepository.findByEmail(appUser.getEmail());
        boolean userExists = user.isPresent();
        if(userExists) {
            // TODO: check if it matches all attributes.
            // TODO: find if email not confirmed send confirmation email again.
            if(user.get().getPassword().equals(bCryptPasswordEncoder.encode(appUser.getPassword()))){
                if(!user.get().isCredentialsNonExpired() && confirmationTokenService.findUsers(user.get()).get().getExpiresAt().isBefore(LocalDateTime.now())){
                    String token = UUID.randomUUID().toString();
                    ConfirmationToken confirmationToken = new ConfirmationToken(
                            token,
                            LocalDateTime.now(),
                            LocalDateTime.now().plusMinutes(15),
                            appUser
                    );
                    confirmationTokenService.saveConfirmationToken(confirmationToken);
                    return token;
                }
                throw new IllegalStateException("Email already sent, clock on the link provided or wait for it to expire.");
            }
            throw new IllegalStateException("Email already taken by another user!");
        }
        String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());
        appUser.setPassword(encodedPassword);
        appUserRepository.save(appUser);

        String token = UUID.randomUUID().toString();
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
        );
        confirmationTokenService.saveConfirmationToken(confirmationToken);

        // TODO: Send Email
        return token;
    }

    public void enableAppUser(String email) {
        AppUser user = appUserRepository.findByEmail(email).get();
        user.setEnabled(true);
        appUserRepository.save(user);
    }
}
