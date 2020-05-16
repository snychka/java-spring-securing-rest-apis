package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

//import org.springframework.security.core.userdetails.UserNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public class UserRepositoryUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    public UserRepositoryUserDetailsService(UserRepository users) {
        this.users = users;
    }
    @Override
    public UserDetails loadUserByUsername(String username) {
        //throw new UserNotFoundException("invalid user");

        throw new UsernameNotFoundException("invalid user");
    }

    private static class BridgeUser extends User implements UserDetails {
        public BridgeUser(User user) {
            super(user);
        }

        public List<GrantedAuthority> getAuthorities() {
            return this.userAuthorities.stream()
                    .map(UserAuthority::getAuthority)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        public boolean isAccountNonExpired() {
            return this.enabled;
        }

        public boolean isAccountNonLocked() {
            return this.enabled;
        }

        public boolean isCredentialsNonExpired() {
            return this.enabled;
        }
    }
}
