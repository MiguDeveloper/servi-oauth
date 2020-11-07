package pe.tuna.servioauth.services;

import pe.tuna.commonsusuarios.models.Usuario;

public interface IUsuarioService {
    public Usuario findByUsername(String username);
}
