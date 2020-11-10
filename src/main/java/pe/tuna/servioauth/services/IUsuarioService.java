package pe.tuna.servioauth.services;

import pe.tuna.commonsusuarios.models.Usuario;

public interface IUsuarioService {
    public Usuario findByUsername(String username);
    public Usuario updateUsuario(Usuario usuario, Long id);
}
