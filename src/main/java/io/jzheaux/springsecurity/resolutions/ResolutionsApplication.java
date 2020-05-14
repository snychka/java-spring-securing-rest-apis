package io.jzheaux.springsecurity.resolutions;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;



import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.sql.DataSource;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

@SpringBootApplication
public class ResolutionsApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResolutionsApplication.class, args);
	}

	@Bean
	UserDetailsService userDetailsService(DataSource dataSource) {
		// ...


			return new JdbcUserDetailsManager(dataSource);

			/*
			return new JdbcUserDetailsManager(dataSource) {
				@Override
				protected List<GrantedAuthority> loadUserAuthorities(String username) {
					return AuthorityUtils.createAuthorityList("READ");
				}
			};
			*/

		/*
		// need to add a .build()
		return new InMemoryUserDetailsManager(
				org.springframework.security.core.userdetails.User
						.withUsername("user")
						.password("{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W")
						.authorities("READ").build());

		 */

		/*
		Vector v = new Vector();
		v.add(org.springframework.security.core.userdetails.User
				.withUsername("user")
				.password("{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W")
				.authorities("READ"));
		return new InMemoryUserDetailsManager(v);
		 */
	}

}
