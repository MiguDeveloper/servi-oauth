package pe.tuna.servioauth.security.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        UserDetails user = (UserDetails) authentication.getPrincipal();
        String mensaje = "Success Login: " + user.getUsername();
        log.info(mensaje);
        System.out.println(mensaje);
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException e, Authentication authentication) {
        String mensaje = "Error en el Login: " + e.getMessage();
        log.error(mensaje);
        System.out.println(mensaje);
    }
}
