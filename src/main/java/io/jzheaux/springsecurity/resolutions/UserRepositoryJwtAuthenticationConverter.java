package io.jzheaux.springsecurity.resolutions;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class UserRepositoryJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final UserRepository users;
    private final JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public UserRepositoryJwtAuthenticationConverter(UserRepository users) {
        this.users = users;
        this.grantedAuthoritiesConverter.setAuthorityPrefix("");
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String username = jwt.getSubject();
        return this.users.findByUsername(username)
                .map(user -> {
                    Collection<GrantedAuthority> authorities = this.grantedAuthoritiesConverter.convert(jwt);
                    return new JwtAuthenticationToken(jwt, authorities);
                }).orElseThrow(() -> new UsernameNotFoundException("no user"));
    }
}
