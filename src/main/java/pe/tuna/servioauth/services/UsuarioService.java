package pe.tuna.servioauth.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pe.tuna.commonsusuarios.models.Usuario;
import pe.tuna.servioauth.clients.UsuarioFeignClient;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UsuarioService implements UserDetailsService, IUsuarioService {

    private static final Logger log = LoggerFactory.getLogger(UsuarioService.class);

    @Autowired
    private UsuarioFeignClient client;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Usuario usuario = client.findByUsername(username);
        if (usuario == null) {
            log.error("Error en el login, el usuario: " + username + " no existe en la BD");
            throw new UsernameNotFoundException("Error en el login, el usuario: "
                    + username + " no existe en la BD");
        }

        List<GrantedAuthority> authorities = usuario.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getNombre()))
                .peek(authority -> log.info("Rol: " + authority.getAuthority()))
                .collect(Collectors.toList());
        log.info("Usuario autenticado: " + username);

        return new User(usuario.getUsername(), usuario.getPassword(), usuario.isEnable(),
                true, true, true, authorities);
    }

    @Override
    public Usuario findByUsername(String username) {
        return client.findByUsername(username);
    }
}
