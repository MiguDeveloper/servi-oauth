package pe.tuna.servioauth.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import pe.tuna.commonsusuarios.models.Usuario;

@FeignClient(name = "servicio-usuarios")
public interface UsuarioFeignClient {
    @GetMapping("/usuarios/search/buscar-username")
    public Usuario findByUsername(@RequestParam String username);
}
