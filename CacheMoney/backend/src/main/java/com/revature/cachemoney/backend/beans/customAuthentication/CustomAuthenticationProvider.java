package com.revature.cachemoney.backend.beans.customAuthentication;

import com.amdelamar.jotp.OTP;
import com.amdelamar.jotp.type.Type;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.revature.cachemoney.backend.beans.repositories.UserRepo;
import com.revature.cachemoney.backend.beans.models.User;

import java.util.Optional;


public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

    @Autowired
    private UserRepo userRepository;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService,
                                        PasswordEncoder passwordEncoder) {
        super();
        this.setUserDetailsService(userDetailsService);
        this.setPasswordEncoder(passwordEncoder);
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // TODO: (DONE login) we can provide extra authentication checks here.

        // `authentication.getName()` gives use the username that is trying to log in
        // `(CustomAuthenticationDetails) authentication.getDetails()` gives us an object
        //     which has extra info that the user provided when they tried to log in.

        User user = userRepository.findByUsername(authentication.getName());

        if (user != null){

            try {
                String serverGeneratedCode = OTP.create(user.getSecret(), OTP.timeInHex(), 6, Type.TOTP);

                CustomAuthenticationDetails userProvidedLoginDetails = (CustomAuthenticationDetails) authentication.getDetails();

                logger.info("Server code " + serverGeneratedCode);
                logger.info("User code " + userProvidedLoginDetails.getUser2FaCode());

                if (!serverGeneratedCode.equals(userProvidedLoginDetails.getUser2FaCode())){
                    throw new BadCredentialsException("User's 2FA code didn't match server code");
                }

            } catch (Exception e) {
                logger.error("Oh no", e);
                throw new AuthenticationServiceException("Failed to generate server-side 2FA code");
            }
        }

        // throw an AuthenticationException, or a subclass like BadCredentialsException here
        // to reject this login attempt.

        return super.authenticate(authentication);
    }

}
