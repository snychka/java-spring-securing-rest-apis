package io.jzheaux.springsecurity.resolutions;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;



import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.sql.DataSource;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import static org.springframework.http.HttpMethod.GET;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResolutionsApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(ResolutionsApplication.class, args);
	}

	@Autowired
	UserRepositoryJwtAuthenticationConverter authenticationConverter;



	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
				.authorizeRequests(authz -> authz
						.anyRequest().authenticated())
            .httpBasic(basic -> {})
				.oauth2ResourceServer(oauth2 -> oauth2
						.jwt().jwtAuthenticationConverter(this.authenticationConverter)
				)
				.cors(cors -> {});

		/*
			http
					.authorizeRequests(authz -> authz
							.anyRequest().authenticated())
					.httpBasic(basic -> {})
					.oauth2ResourceServer(oauth2 -> oauth2.jwt())
					.cors(cors -> {});

		 */


		/*http.authorizeRequests(authz -> authz
						.mvcMatchers(GET, "/resolutions", "/resolution/**").hasAuthority("resolution:read")
						.anyRequest().hasAuthority("resolution:write"))
				.httpBasic(basic -> {});

		 */
	}

	@Bean
	WebMvcConfigurer webMvcConfigurer() {
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**")
						// .maxAge(0) // if using local verification
						.allowedOrigins("http://localhost:4000")
						.allowedMethods("HEAD")
						.allowedHeaders("Authorization");
			}
		};
	}

	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
		JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
		authoritiesConverter.setAuthorityPrefix("");
		authenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
		return authenticationConverter;
	}



	@Bean
	UserDetailsService userDetailsService(UserRepository users) {
		// ...


			return new UserRepositoryUserDetailsService(users);

			//return new JdbcUserDetailsManager(dataSource);

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
