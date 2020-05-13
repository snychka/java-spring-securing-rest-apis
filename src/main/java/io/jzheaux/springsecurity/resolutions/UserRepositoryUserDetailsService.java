package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.HashSet;
import java.util.stream.Collectors;

public class UserRepositoryUserDetailsService implements UserDetailsService {
	private final UserRepository users;

	public UserRepositoryUserDetailsService(UserRepository users) {
		this.users = users;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.users.findByUsername(username)
				.map(this::map)
				.orElseThrow(() -> new UsernameNotFoundException("no user"));
	}

	private BridgedUser map(User user) {
		Collection<GrantedAuthority> authorities = new HashSet<>();
		for (UserAuthority userAuthority : user.getUserAuthorities()) {
			String authority = userAuthority.getAuthority();
			if ("ROLE_ADMIN".equals(authority)) {
				authorities.add(new SimpleGrantedAuthority("resolution:read"));
				authorities.add(new SimpleGrantedAuthority("resolution:write"));
			}
			authorities.add(new SimpleGrantedAuthority(authority));
		}
		return new BridgedUser(user, authorities);
	}

	private static class BridgedUser extends User implements UserDetails {
		private final Collection<GrantedAuthority> authorities;

		public BridgedUser(User user, Collection<GrantedAuthority> authorities) {
			super(user);
			this.authorities = authorities;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public boolean isAccountNonExpired() {
			return this.enabled;
		}

		@Override
		public boolean isAccountNonLocked() {
			return this.enabled;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return this.enabled;
		}
	}
}
