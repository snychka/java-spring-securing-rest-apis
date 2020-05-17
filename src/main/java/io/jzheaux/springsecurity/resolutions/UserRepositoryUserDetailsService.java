package io.jzheaux.springsecurity.resolutions;

/*
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

//import org.springframework.security.core.userdetails.UserNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

 */

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import io.jzheaux.springsecurity.resolutions.User;
import io.jzheaux.springsecurity.resolutions.UserAuthority;
import io.jzheaux.springsecurity.resolutions.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

// STEEFAN: needed to implement all 3 interfaces
public class UserRepositoryUserDetailsService implements Serializable, UserDetails, UserDetailsService {

    private final UserRepository users;

    public UserRepositoryUserDetailsService(UserRepository users) {
        this.users = users;
    }

    /*
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return null;
    }

     */


    /*
    @Override
    public UserDetails loadUserByUsername(String username) {
        return this.users.findByUsername(username)
                .map(BridgeUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("invalid user"));

    }
     */

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.users.findByUsername(username)
                .map(this::map)
                .orElseThrow(() -> new UsernameNotFoundException("no user"));
    }


    private static class BridgeUser extends User implements UserDetails {
        private  Collection<GrantedAuthority> authorities;

        public BridgeUser(User user, Collection<GrantedAuthority> authorities) {
            super(user);
            this.authorities = authorities;
        }

        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.authorities;
        }

        /*
        public BridgeUser(User user) {
            super(user);
        }

        public List<GrantedAuthority> getAuthorities() {
            return this.userAuthorities.stream()
                    .map(UserAuthority::getAuthority)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        */

        public boolean isAccountNonExpired() {
            return this.enabled;
        }

        public boolean isAccountNonLocked() {
            return this.enabled;
        }

        public boolean isCredentialsNonExpired() {
            return this.enabled;
        }

        // STEFAN: needed to create
        public String getPassword() {
            return this.password;
        }

        // STEFAN: needed to create
        public String getUsername() {
            return this.username;
        }

        // STEFAN: needed to create
        public boolean isEnabled() {
            return this.enabled;
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    // STEFAN: needed to create
    public String getPassword() {
        return this.getPassword();
    }

    // STEFAN: needed to create
    public String getUsername() {
        return this.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    // STEFAN: needed to create
    public boolean isEnabled() {
        return true;
    }


    private BridgeUser map(User user) {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        for (UserAuthority userAuthority : user.getUserAuthorities()) {
            String authority = userAuthority.getAuthority();
            if ("ROLE_ADMIN".equals(authority)) {
                authorities.add(new SimpleGrantedAuthority("resolution:read"));
                authorities.add(new SimpleGrantedAuthority("resolution:write"));
            }
            authorities.add(new SimpleGrantedAuthority(authority));
        }
        return new BridgeUser(user, authorities);
    }
}

