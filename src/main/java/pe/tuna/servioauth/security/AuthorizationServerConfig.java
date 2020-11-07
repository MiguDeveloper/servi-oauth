package pe.tuna.servioauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    // la clase InfoAdicionalToken un @Component podemos inyectarlo
    @Autowired
    private InfoAdicionalToken infoAdicionalToken;

    // Usamos este metodo para exponer dos endpoints que no estan expuestos que son:
    // tokenKeyAccess:  habilita la ruta de generacion de token POST: /oauth/token
    // checkTokenAccess: se encarga de validar el token
    // '/oauth/check_token' y '/oauth/token_key'
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    // Este metodo nos permite configurar nuestras aplicaciones clientes:
    // llames un SPA como angular, react, vue, etc. android
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient("angularApp")
                .secret(passwordEncoder.encode("12345"))
                .scopes("read", "write")
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(3600);// si quiremos una app mas pondriamos .and().with...
    }

    // este metodo esta relacionado al endpoint de oauth2 del server de autorizacion
    // que se encarga de generar el token la URI es: POST /oauth/token
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // aniadimos info adicional al token, tener en cuenta que debemos de poner la info
        // que ya tiene en un inicio el token es decir 'accessTokenConverter'
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(infoAdicionalToken, accessTokenConverter()));

        // en el accessTokenConverter le indicamos que sea de tipo JWT token, es decir lo crea
        // con el tokenStore: almacena y generamos el token con los datos del accessTokenConverter
        endpoints.authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(tokenEnhancerChain);
    }

    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey("nuestraFirmaSecretaQueIraEnElServidorDeConfiguracion");
        // jwtAccessTokenConverter.setVerifierKey("conEstaFirmaVerificamos");
        return jwtAccessTokenConverter;
    }
}
