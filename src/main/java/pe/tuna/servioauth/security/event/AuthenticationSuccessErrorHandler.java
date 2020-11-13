package pe.tuna.servioauth.security.event;

import brave.Tracer;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import pe.tuna.commonsusuarios.models.Usuario;
import pe.tuna.servioauth.services.IUsuarioService;

@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

    @Autowired
    private IUsuarioService usuarioService;

    @Autowired
    private Environment env;

    @Autowired
    private Tracer tracer;

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        if (authentication.getName().equalsIgnoreCase(env.getProperty("config.security.oauth.cliente.id"))) {
            return;
        }
        UserDetails user = (UserDetails) authentication.getPrincipal();
        String mensaje = "Success Login: " + user.getUsername();
        log.info(mensaje);
        System.out.println(mensaje);

        // aqui no es necesario el try ya que si existe el usuario logeado
        Usuario usuario = usuarioService.findByUsername(user.getUsername());
        if (usuario.getIntentos() > 0) {
            usuario.setIntentos(0);
            usuarioService.updateUsuario(usuario, usuario.getId());
        }
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException e, Authentication authentication) {

        String mensaje = "Error en el login " + e.getMessage();
        log.error(mensaje);
        System.out.println(mensaje);
        try {
            StringBuilder errors = new StringBuilder();
            errors.append(mensaje);

            Usuario usuario = usuarioService.findByUsername(authentication.getName());
            log.info(String.format("Intento %s de login antes incre.", usuario.getIntentos()));
            usuario.setIntentos(usuario.getIntentos() + 1);
            log.info(String.format("Intento %s de login despues incre.", usuario.getIntentos()));

            errors.append(" - Intentos del login: " + usuario.getIntentos());

            if (usuario.getIntentos() >= 3) {
                String errorMaxIntentos = String.format("El usuario %s deshabilitado por maximo numero de intentos",
                        usuario.getNombre());
                log.error(errorMaxIntentos);

                errors.append(" - " + errorMaxIntentos);

                usuario.setEnable(false);
            }
            usuarioService.updateUsuario(usuario, usuario.getId());
            tracer.currentSpan().tag("error.mensaje", errors.toString());
        } catch (FeignException ex) {
            log.error(String.format("El usuario %s no existe en el sistema", authentication.getName()));

        }

    }
}
