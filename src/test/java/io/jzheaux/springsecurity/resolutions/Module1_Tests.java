package io.jzheaux.springsecurity.resolutions;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.data.repository.CrudRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Repository;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@SpringBootTest
public class Module1_Tests {

	@Autowired
	MockMvc mvc;

	@Autowired(required = false)
	UserDetailsService userDetailsService;

	@Autowired(required = false)
	CrudRepository<User, UUID> users;

	@Autowired
	ApplicationContext context;

	/**
	 * Add the appropriate Spring Boot starter dependency
	 */
	@Test
	public void task_1() throws Exception {
		assertNotNull(
				"Task 1: Couldn't find a `UserDetailsService` in the application context. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from teh `@SpringBootApplication` annotation.",
				this.userDetailsService);

		MvcResult result = this.mvc.perform(get("/resolutions"))
				.andReturn();

		assertEquals(
				"Task 1: The `/resolutions` endpoint isn't protected. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from the `@SpringBootApplication` annotation.",
				result.getResponse().getStatus(), 401);

		String wwwAuthenticate = result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE);
		assertNotNull(
				"Task 1: The `/resolutions` response is missing the `WWW-Authenticate` response header. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from the `@SpringBootApplication` annotation.",
				wwwAuthenticate);

		assertTrue(
				"Task 1: The `/resolutions` response's `WWW-Authenticate` header is [" + wwwAuthenticate + "], but `Basic` is what is expected at this point in the project. " +
						"Make sure that you've removed the `SecurityAutoConfiguration` exclusion from the `@SpringBootApplication` annotation.",
				wwwAuthenticate.startsWith("Basic"));
	}

	@Test
	public void task_2() throws Exception {
		// add InMemoryUserDetailsManager
		task_1();
		String failureMessage = assertUserDetailsService(InMemoryUserDetailsManager.class);
		if (failureMessage != null) {
			fail("Task 2: " + failureMessage);
		}

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 2: The `/resolutions` response failed to authorize user/password as the username and password. " +
						"Make sure that your `UserDetailsService` is wired with a password of `password`.",
				result.getResponse().getStatus(), 200);
	}

	@Test
	public void task_3() throws Exception {
		// create User
		task_1();
		Entity userEntity = User.class.getAnnotation(Entity.class);

		assertTrue(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the Users class needs to be annotated with `@javax.persistence.Entity(name=\"users\")` since that's the table name that the " +
						"manager expects",
				userEntity != null && "users".equals(userEntity.name()));

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a JPA field mapped to the `username` column.",
				ReflectedUser.usernameColumnField);

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a JPA field mapped to the `password` column.",
				ReflectedUser.passwordColumnField);

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a JPA field mapped to the `enabled` column.",
				ReflectedUser.enabledColumnField);
	}

	@Test
	public void task_4() throws Exception {
		// create UserRepository
		task_3(); // check that everything from Task 3 still holds
		assertNotNull(
				"Task 4: Make sure that your `UserRepository` is extending `CrudRepository<User,UUID>`",
				this.users);

		assertNotNull(
				"Task 4: Make sure that your `UserRepository` is annotated with " + Repository.class,
				UserRepository.class.getAnnotation(Repository.class));
	}

	@Test
	public void task_5() throws Exception {
		// add users to database
		task_4(); // make sure everything from task_4 still holds
		Iterable<User> users = this.users.findAll();
		Map<String, ReflectedUser> usersByUsername = StreamSupport.stream(users.spliterator(), false)
				.map(ReflectedUser::new)
				.collect(Collectors.toMap(ReflectedUser::getUsername, Function.identity()));

		ReflectedUser user = usersByUsername.get("user");
		assertNotNull(
				"Task 5: To ensure that future tests work, make sure that that `UserRepository` has at least a user " +
						"whose username is `user`",
				user);

		String storedPassword = user.getPassword();
		assertNotEquals(
				"Task 5: Make sure that the password you add to the database is encoded",
				"password", storedPassword);
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		assertTrue(
				"Task 5: Make sure that you are using the default password encoder to encode the user's password " +
						"before persisting. The default password encoder is `PasswordEncoderFactories.createDelegatingPasswordEncoder`",
				encoder.matches("password", storedPassword));
	}

	@Test
	public void task_6() throws Exception {
		// publish JdbcUserDetailsManager
		task_5();
		String failureMessage = assertUserDetailsService(JdbcUserDetailsManager.class);
		if (failureMessage != null) {
			fail("Task 6: " + failureMessage);
		}

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 6: The `/resolutions` endpoint failed to authorize user/password as the username and password. " +
						"Make sure that you're adding the appropriate roles to the user -- since we haven't added authority yet, " +
						"they should be added manually when constructing the `JdbcUserDetailsManager`.",
				result.getResponse().getStatus(), 200);
	}

	@Test
	public void task_7() throws Exception {
		// add UserAuthority
		task_6();
		Entity authorityEntity = UserAuthority.class.getAnnotation(Entity.class);

		assertTrue(
				"Task 7: Since you are using `JdbcUserDetailsManager` to retrieve users, " +
						"the `UserAuthority` class needs to be annotated with `@Entity(name=\"authorities\")` since " +
						"that's the table name that the manager expects by default",
				authorityEntity != null && "authorities".equals(authorityEntity.name()));

		assertNotNull(
				"Task 7: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `UserAuthority` class needs a JPA field mapped to the `authority` column.",
				ReflectedUserAuthority.authorityColumnField);

		assertNotNull(
				"Task 7: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `UserAuthority` class needs a `username` column. JPA can do this with the `@JoinColumn` annotation on a " +
						"field of type `User`.",
				ReflectedUserAuthority.usernameColumnField);

		assertEquals(
				"Task 7: Let's please keep the `User` field and the JPA field for the `username` column the same." +
						"This can be done by introducing a field of ype `User` that uses a `@ManyToOne` annotation and a `@JoinColumn` annotation " +
						"specifying a `name` and `referencedColumnName` of `username`.",
				ReflectedUserAuthority.userField, ReflectedUserAuthority.usernameColumnField);

		assertNotNull(
				"Task 7: Make sure that the `User` field is annotated with `@ManyToOne`",
				ReflectedUserAuthority.userField.getAnnotation(ManyToOne.class));

		assertNotNull(
				"Task 7: Make sure that you've updated `User` to declare its bi-directional relationship to `UserAuthority`. " +
						"There should be a field annotated with `@OneToMany` with a collection of type `UserAuthority`.",
				ReflectedUser.userAuthorityCollectionField);

		assertNotNull(
				"Task 7: Make sure to add a `grantAuthority` method to `User`",
				ReflectedUser.grantAuthorityMethod);

		String authority = UUID.randomUUID().toString();
		ReflectedUser user = ReflectedUser.newInstance();
		try {
			user.grantAuthority(authority);
		} catch (Exception e) {
			fail("Task 7: Tried to grant an authority, but experienced an error: " + e);
		}

		try {
			Collection<UserAuthority> authorities = user.getUserAuthorities();
			assertTrue(
					"Task 7: After granting an authority, the authorities list is still empty. Make sure you are adding " +
							"an authority to your `User`'s authority list when `grantAuthority` is called.",
					authorities.size() > 0);

			Optional<ReflectedUserAuthority> hasRoleUser = authorities.stream()
					.map(ReflectedUserAuthority::new)
					.filter(a -> authority.equals(a.getAuthority()))
					.findFirst();
			assertTrue(
					"Task 7: After granting an authority, the authorities list does not have a matching `UserAuthority`" +
							". Make sure you are setting the authority's value to be what is passed in to " +
							"`grantAuthority`",
					hasRoleUser.isPresent());

			ReflectedUserAuthority userAuthority = hasRoleUser.get();
			ReflectedUser userFromUserAuthority = new ReflectedUser(userAuthority.getUser());
			assertEquals(
					"Task 7: Make sure that the `User` stored in `UserAuthority` matches the `User` instance on which " +
							"`grantAuthority` was called.",
					user.user, userFromUserAuthority.user);
		} catch (Exception e) {
			fail(
					"Task 7: Make sure that the authorities property in `User` is called `userAuthorities`. While not strictly " +
							"necessary, with simplify future steps.");
		}
	}

	@Test
	public void task_8() throws Exception {
		task_7();
		// add additional users with authorities

		try {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername("hasread");
			Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
			assertEquals(
					"Task 8: Make sure the user has only the `READ` authority",
					1, authorities.size());
			assertEquals(
					"Task 8: Make sure the user has only the `READ` authority",
					"READ", authorities.iterator().next().getAuthority());
		} catch (UsernameNotFoundException e) {
			fail(
					"Task 8: Make sure to add a user `hasread` with an encoded password of `password`");
		}

		try {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername("haswrite");
			Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
			assertEquals(
					"Task 8: Make sure the user has only the `WRITE` authority",
					1, authorities.size());
			assertEquals(
					"Task 8: Make sure the user has only the `WRITE` authority",
					"WRITE", authorities.iterator().next().getAuthority());
		} catch (UsernameNotFoundException e) {
			fail(
					"Task 8: Make sure to add a user `haswrite` with an encoded password of `password`");
		}
	}

	@Test
	public void task_9() throws Exception {
		// add simple authorization
		task_8();

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertNotEquals(
				"Task 9: Authentication failed for user `hasread`. Make sure that the password is " +
				"set to 'password'.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 9: Authorization failed for user `hasread`, which has the 'READ' permission. Please " +
				"check your security configuration to make sure that `/resolutions` is only requiring the 'READ' permission.",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 9: `/resolutions` endpoint responded with " + result.getResponse().getStatus() + " " +
				"instead of the expected 200",
				200, result.getResponse().getStatus());

		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertEquals(
				"Task 9: The `/resolution` POST endpoint allowed `hasread` even though it only was " +
						"granted 'READ'. Please check your security configuration to make sure that `/resolution` POST is " +
						"requiring the 'WRITE' permission",
				403, result.getResponse().getStatus());

		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic("haswrite", "password")))
				.andReturn();

		assertNotEquals(
				"Task 9: Authentication failed for user `haswrite`. Make sure that the password is " +
				"set to 'password'.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 9: Authorization failed for user `haswrite`, which has the 'WRITE' permission. Please " +
				"check your security configuration to make sure that `/resolution` POST is only requiring the 'WRITE' permission.",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 9: The `/resolution` POST endpoint responded with " + result.getResponse().getStatus() + " " +
				"instead of the expected 200",
				200, result.getResponse().getStatus());
	}

	@Test
	public void task_10() throws Exception {
		// add User copy constructor
		task_9();
		assertNotNull(
				"Task 10: Couldn't find a copy constructor in `User` class.",
				ReflectedUser.copyConstructor);

		ReflectedUser user = new ReflectedUser(this.users.findAll().iterator().next());
		try {
			ReflectedUser copy = ReflectedUser.copiedInstance(user);
			assertEquals(
					"Task 10: The usernames of the original and its copy are different.",
					user.getUsername(),
					copy.getUsername());

			assertEquals(
					"Task 10: The passwords of the original and its copy are different.",
					user.getPassword(),
					copy.getPassword());

			Collection<String> userAuthorities = user.getUserAuthorities().stream()
					.map(ua -> new ReflectedUserAuthority(ua).getAuthority())
					.collect(Collectors.toList());
			Collection<String> copyAuthorities = copy.getUserAuthorities().stream()
					.map(ua -> new ReflectedUserAuthority(ua).getAuthority())
					.collect(Collectors.toList());
			assertEquals(
					"Task 10: The authorities of the original and its copy are different.",
					userAuthorities,
					copyAuthorities);
		} catch (Exception e) {
			fail("Task 10: `User`'s copy constructor threw an exception: " + e);
		}
	}

	@Test
	public void task_11() throws Exception {
		// add custom UserDetailsService
		task_1();

		String failureMessage = assertUserDetailsService(UserRepositoryUserDetailsService.class);
		if (failureMessage != null) {
			fail("Task 11: " + failureMessage);
		}

		try {
			this.userDetailsService.loadUserByUsername(UUID.randomUUID().toString());
			fail("Task 11: Make sure your custom `UserDetailsService` throws a `UsernameNotFoundException` when it can't find a user");
		} catch (UsernameNotFoundException expected) {
			// ignoring
		} catch (Exception e) {
			fail("Task 11: Make sure your custom `UserDetailsService` throws a `UsernameNotFoundException` when it can't find a user");
		}

		Field userRepositoryField = getDeclaredFieldByType(UserRepositoryUserDetailsService.class, UserRepository.class);
		assertNotNull(
				"Task 11: For this exercise make sure that your custom UserDetailsService implementation is delegating to " +
						"a `UserRepository` instance",
				userRepositoryField);

		UserDetails user = this.userDetailsService.loadUserByUsername("user");

		assertTrue(
				"Task 11: The object returned from a custom `UserDetailsService` should be castable to your custom " +
						"`User` type.",
				User.class.isAssignableFrom(user.getClass()));

		assertTrue(
				"Task 11: The object returned from a custom `UserDetailsService` must be castable to `UserDetails`",
				UserDetails.class.isAssignableFrom(user.getClass()));

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 11: The `/resolutions` response failed to authorize `user`/`password` as the username and password. " +
						"Make sure that your custom `UserDetailsService` is wired with a password of `password`.",
				result.getResponse().getStatus(), 200);
	}

	private enum UserDetailsServiceVerifier {
		INMEMORY(InMemoryUserDetailsManager.class, Module1_Tests::assertInMemoryUserDetailsService),
		JDBC(JdbcUserDetailsManager.class, Module1_Tests::assertJdbcUserDetailsService),
		CUSTOM(UserRepositoryUserDetailsService.class, Module1_Tests::assertCustomUserDetailsService);

		Class<?> clazz;
		Function<UserDetailsService, String> verifier;

		UserDetailsServiceVerifier(Class<?> clazz,
								   Function<UserDetailsService, String> verifier) {
			this.clazz = clazz;
			this.verifier = verifier;
		}

		String verify(UserDetailsService userDetailsService) {
			return this.verifier.apply(userDetailsService);
		}

		static UserDetailsServiceVerifier fromClass(Class<?> clazz) {
			for (UserDetailsServiceVerifier verifier : values()) {
				if (verifier.clazz.isAssignableFrom(clazz)) {
					return verifier;
				}
			}
			throw new NoSuchElementException("error!");
		}
	}

	private String assertUserDetailsService(Class<?> simplestAllowedUserDetailsService) {
		UserDetailsServiceVerifier minimum = UserDetailsServiceVerifier.fromClass(simplestAllowedUserDetailsService);

		try {
			UserDetailsServiceVerifier verifier = UserDetailsServiceVerifier.fromClass(this.userDetailsService.getClass());
			if (verifier.ordinal() < minimum.ordinal()) {
				return "The `UserDetailsService` bean is not of type `" + minimum.clazz.getName() + "`. Please double-check " +
						"the type you are returning for your `UserDetailsService` `@Bean`.";
			}
			return verifier.verify(this.userDetailsService);
		} catch (NoSuchElementException e) {
			return "Could not find a `UserDetailsService` of the right type. " +
					"Please double-check the `@Bean` that you are exposing";
		}
	}

	static String assertInMemoryUserDetailsService(UserDetailsService userDetailsService) {
		UserDetails user = userDetailsService.loadUserByUsername("user");
		if (user == null) {
			return "Make sure that your `InMemoryUserDetailsManager` is wired with a username of 'user'. " +
					"This is usually done by calling building a `User` with `User#withUsername`.";
		}

		return null;
	}

	static String assertJdbcUserDetailsService(UserDetailsService userDetailsService) {
		UserDetails user = userDetailsService.loadUserByUsername("user");
		if (user == null) {
			return "Make sure that your user database table has a user with a username of `user`.";
		}

		return null;
	}

	static String assertCustomUserDetailsService(UserDetailsService userDetailsService) {
		UserDetails user = userDetailsService.loadUserByUsername("user");
		if (user == null) {
			return "Make sure that your custom `UserDetailsService` has a user with a username of `user`. " +
					"This should be provided via the `UserRepository` which is pointing to your user database table.";
		}

		return null;
	}

	private static class ReflectedUser {
		static Constructor defaultConstructor;
		static Constructor copyConstructor;
		static Field usernameColumnField;
		static Field passwordColumnField;
		static Field enabledColumnField;
		static Field userAuthorityCollectionField;
		static Method grantAuthorityMethod;

		static {
			defaultConstructor = getConstructor(User.class);
			if (defaultConstructor != null) defaultConstructor.setAccessible(true);
			copyConstructor = getConstructor(User.class, User.class);
			usernameColumnField = getDeclaredFieldByColumnName(User.class, "username");
			if (usernameColumnField != null) usernameColumnField.setAccessible(true);
			passwordColumnField = getDeclaredFieldByColumnName(User.class, "password");
			if (passwordColumnField != null) passwordColumnField.setAccessible(true);
			enabledColumnField = getDeclaredFieldByColumnName(User.class, "enabled");
			if (enabledColumnField != null) enabledColumnField.setAccessible(true);
			userAuthorityCollectionField = getDeclaredFieldHavingAnnotation(User.class, OneToMany.class);
			if (userAuthorityCollectionField != null) userAuthorityCollectionField.setAccessible(true);
			try {
				grantAuthorityMethod = User.class.getDeclaredMethod("grantAuthority", String.class);
			} catch (Exception ignored) {
				// user hasn't added this method yet
			}
		}

		User user;

		public static ReflectedUser newInstance() {
			try {
				return new ReflectedUser((User) defaultConstructor.newInstance());
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		public static ReflectedUser copiedInstance(ReflectedUser user) {
			try {
				return new ReflectedUser((User) copyConstructor.newInstance(user.user));
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		public ReflectedUser(User user) {
			this.user = user;
		}

		String getUsername() {
			return getProperty(this.user, usernameColumnField);
		}

		String getPassword() {
			return getProperty(this.user, passwordColumnField);
		}

		Collection<UserAuthority> getUserAuthorities() {
			return getProperty(this.user, userAuthorityCollectionField);
		}

		void grantAuthority(String authority) {
			try {
				grantAuthorityMethod.invoke(this.user, authority);
			} catch (Exception e) {
				throw new RuntimeException("Failed to call `grantAuthority` on " + this.user, e);
			}
		}
	}

	private static class ReflectedUserAuthority {
		static Field userField;
		static Field usernameColumnField;
		static Field authorityField;
		static Field authorityColumnField;

		static {
			userField = getDeclaredFieldByType(UserAuthority.class, User.class);
			if (userField != null) userField.setAccessible(true);
			usernameColumnField = getDeclaredFieldByColumnName(UserAuthority.class, "username");
			authorityField = getDeclaredFieldByName(UserAuthority.class, "authority");
			authorityColumnField = getDeclaredFieldByColumnName(UserAuthority.class, "authority");
			if (authorityColumnField != null) authorityColumnField.setAccessible(true);
		}

		UserAuthority userAuthority;

		public ReflectedUserAuthority(UserAuthority userAuthority) {
			this.userAuthority = userAuthority;
		}

		User getUser() {
			return getProperty(this.userAuthority, userField);
		}

		String getAuthority() {
			return getProperty(this.userAuthority, authorityColumnField);
		}
	}

	static Field getDeclaredFieldByType(Class<?> type, Class<?> fieldType) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getType() == fieldType)
				.findFirst().orElse(null);
	}

	static Field getDeclaredFieldByName(Class<?> type, String name) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getName().equals(name))
				.findFirst().orElse(null);
	}

	static Field getDeclaredFieldByColumnName(Class<?> type, String columnName) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> {
					String name = null;
					Column column = f.getAnnotation(Column.class);
					Id id = f.getAnnotation(Id.class);
					JoinColumn joinColumn = f.getAnnotation(JoinColumn.class);

					if (column != null) {
						name = column.name();
					} else if (joinColumn != null) {
						name = joinColumn.name();
					} else if (id != null) {
						name = "";
					}

					if ("".equals(name)) {
						name = f.getName();
					}

					return name.equals(columnName);
				})
				.findFirst().orElse(null);
	}

	static Field getDeclaredFieldHavingAnnotation(Class<?> type, Class<? extends Annotation> annotation) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getAnnotation(annotation) != null)
				.findFirst().orElse(null);
	}

	static Constructor<?> getConstructor(Class<?> type, Class<?>... parameterTypes) {
		try {
			return type.getDeclaredConstructor(parameterTypes);
		} catch (Exception ignored) {
			return null;
		}
	}

	private static <T> T getProperty(Object o, Field field) {
		try {
			field.setAccessible(true);
			return (T) field.get(o);
		} catch (Exception e) {
			throw new RuntimeException("Tried to get " + field + " from " + o, e);
		}
	}
}
