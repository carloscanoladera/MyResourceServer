package my.springboot.developerblog.ws.api.myresourceserver.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class JWTSecurityConfig {

    //https://keycloak.discourse.group/t/invalid-token-on-docker-an-error-occurred-while-attempting-to-decode-the-jwt-invalid-token/16532/2
  /*  had the same problem with a Java Spring Backend, after a lot of google searches, I found out that there were incompatibilities between Signature Algorithm used by spring boot and keycloak.

    As part of the initiation I specified SignatureAlgorithm.RS256 in the application and also ensured that same algorithm was used for the realm/client.
  */
    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**")
                //.hasAuthority("SCOPE_profile")
                .hasAnyRole("developer")
        .anyRequest().authenticated().and().csrf().disable().oauth2ResourceServer(oauth2 -> oauth2.jwt());

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).jwsAlgorithm(SignatureAlgorithm.RS256).build();
    }
}