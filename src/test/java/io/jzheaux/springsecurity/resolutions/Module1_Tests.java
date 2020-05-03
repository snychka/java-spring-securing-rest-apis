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
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.ClassUtils;

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
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
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

	@Autowired
	ApplicationContext context;

	/**
	 * Add the appropriate Spring Boot starter dependency
	 */
	@Test
	public void task_1() throws Exception {
		assertTrue(
				"Task 1: Couldn't find Spring Security on the classpath. " +
						"Make sure to add `spring-boot-starter-security` as a Maven dependency.",
				ClassUtils.isPresent("org.springframework.security.core.userdetails.UserDetailsService", this.getClass().getClassLoader()));

		Class<?> userDetailsService = Class.forName("org.springframework.security.core.userdetails.UserDetailsService");
		assertTrue(
				"Task 1: Couldn't find a `UserDetailsService` in the application context. " +
						"Make sure that the Spring Boot starter Maven dependency you added is `spring-boot-starter-security`.",
				this.context.getBeanNamesForType(userDetailsService).length > 0);

		MvcResult result = this.mvc.perform(get("/resolutions"))
				.andReturn();

		assertEquals(
				"Task 1: The `/resolutions` endpoint isn't protected. " +
						"Make sure that the Spring Boot starter Maven dependency you added is `spring-boot-starter-security`.",
				result.getResponse().getStatus(), 401);

		String wwwAuthenticate = result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE);
		assertNotNull(
				"Task 1: The `/resolutions` response is missing the `WWW-Authenticate` response header. " +
						"Make sure that the Spring Boot starter Maven dependency you added is `spring-boot-starter-security`.",
				wwwAuthenticate);

		assertTrue(
				"Task 1: The `/resolutions` response's `WWW-Authenticate` header is [" + wwwAuthenticate + "], but `Basic` is what is expected at this point in the project. " +
						"Make sure that the Spring Boot starter Maven dependency you added is `spring-boot-starter-security`.",
				wwwAuthenticate.startsWith("Basic"));
	}

	@Test
	public void task_2() throws Exception {
		// add InMemoryUserDetailsManager
		task_1();

		Class<?> userDetailsManagerClass = Class.forName("org.springframework.security.provisioning.InMemoryUserDetailsManager");
		assertTrue(
				"Task 2: Couldn't find a `UserDetailsService` of type `InMemoryUserDetailsManager` in the application context. " +
						"Make sure that you are exposing a `@Bean` of that type.",
				this.context.getBeanNamesForType(userDetailsManagerClass).length > 0);

		Object userDetailsService = this.context.getBean(userDetailsManagerClass);
		Field field = userDetailsManagerClass.getDeclaredField("users");
		field.setAccessible(true);
		Map users = (Map) field.get(userDetailsService);
		assertTrue(
				"Task 2: Make sure that your `InMemoryUserDetailsManager` is wired with a username of 'user'.",
				users.containsKey("user"));

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 2: The `/resolutions` response failed to authorize user/password as the username and password. " +
						"Make sure that your `InMemoryUserDetailsManager` is wired with a password of `password`.",
				result.getResponse().getStatus(), 200);
	}

	@Test
	public void task_3() throws Exception {
		// create User
		task_2();
		assertUserStructure();
	}

	@Test
	public void task_4() throws Exception {
		// create UserRepository
		task_3(); // check that everything from Task 3 still holds
		assertUserRepositoryStructure();
	}

	@Test
	public void task_5() throws Exception {
		// add users to database
		task_4(); // make sure everything from task_4 still holds
		assertDatabaseContents();
	}

	@Test
	public void task_6() throws Exception {
		// publish JdbcUserDetailsManager
		task_1(); // ensure everything from task_1 still works
		assertUserStructure();
		assertUserRepositoryStructure();
		assertDatabaseContents();

		Class<?> userDetailsServiceClass = Class.forName("org.springframework.security.core.userdetails.UserDetailsService");
		assertEquals(
				"Task 6: Make sure there is exactly one `UserDetailsService` in the application context. It should be " +
						"exposed as a `@Bean`.",
				1, this.context.getBeanNamesForType(userDetailsServiceClass).length);

		Class<?> jdbcUserDetailsManagerClass = Class.forName("org.springframework.security.provisioning.JdbcUserDetailsManager");
		assertEquals(
				"Task 6: Couldn't find a `UserDetailsService` of type `JdbcUserDetailsManager` in the application context. " +
						"Make sure that you are exposing a `@Bean` of that type.",
				1, this.context.getBeanNamesForType(jdbcUserDetailsManagerClass).length);

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
		assertUserAuthorityStructure();
	}

	@Test
	public void task_8() throws Exception {
		// add simple authorization
		task_7();
		Object withRead = findUserWithAuthority("READ");
		assertNotNull(
				"Task 8: Make sure that you've added a user that at least has been granted 'READ' authority",
				withRead);

		String withReadUsername = getProperty(withRead, "username");
		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic(withReadUsername, "password")))
				.andReturn();

		if (result.getResponse().getStatus() == 401) {
			fail("Task 8: Authentication failed for user " + withReadUsername + ". Make sure that the password is " +
					"set to 'password'.");
		}

		if (result.getResponse().getStatus() == 403) {
			fail("Task 8: Authorization failed for user " + withReadUsername + ", which has the 'READ' permission. Please " +
					"check your security configuration to make sure that `/resolutions` is only requiring the 'READ' permission.");
		}

		if (result.getResponse().getStatus() != 200) {
			fail("Task 8: `/resolutions` endpoint responded with " + result.getResponse().getStatus() + " " +
					"instead of the expected 200");
		}

		Collection<String> authorities = new SpringSecurityClasspathGuard(this.context)
				.getUserAuthorities(withReadUsername);
		if (!authorities.contains("WRITE")) {
			result = this.mvc.perform(post("/resolution")
					.content("my resolution")
					.with(csrf())
					.with(httpBasic(withReadUsername, "password")))
					.andReturn();

			assertEquals(
					"Task 8: The `/resolution` POST endpoint allowed " + withReadUsername + " even though it only was " +
							"granted 'READ'. Please check your security configuration to make sure that `/resolution` POST is " +
							"requiring the 'WRITE' permission",
					403, result.getResponse().getStatus());
		}

		Object withWrite = findUserWithAuthority("WRITE");
		assertNotNull(
				"Task 8: Make sure that you've added a user that at least has been granted 'WRITE' authority",
				withWrite);

		String withWriteUsername = getProperty(withWrite, "username");
		result = this.mvc.perform(post("/resolution")
				.content("my resolution")
				.with(csrf())
				.with(httpBasic(withWriteUsername, "password")))
				.andReturn();

		if (result.getResponse().getStatus() == 401) {
			fail("Task 8: Authentication failed for user " + withWriteUsername + ". Make sure that the password is " +
					"set to 'password'.");
		}

		if (result.getResponse().getStatus() == 403) {
			fail("Task 8: Authorization failed for user " + withWriteUsername + ", which has the 'WRITE' permission. Please " +
					"check your security configuration to make sure that `/resolution` POST is only requiring the 'WRITE' permission.");
		}

		if (result.getResponse().getStatus() != 200) {
			fail("Task 8: The `/resolution` POST endpoint responded with " + result.getResponse().getStatus() + " " +
					"instead of the expected 200");
		}
	}

	@Test
	public void task_9() throws Exception {
		// add User copy constructor
		task_8();
		Class<?> userClass = assertClass("Task 9", "io.jzheaux.springsecurity.resolutions.User");
		Constructor<?> userCopyConstructor = getConstructor(userClass, userClass);
		assertNotNull(
				"Task 9: Couldn't find a copy constructor in `User` class.",
				userCopyConstructor);

		Object user = findUserWithAuthority("READ");
		try {
			Object copy = userCopyConstructor.newInstance(user);
			Field usernameField = getDeclaredFieldByColumnName(userClass, "username");
			String userUsername = getProperty(user, usernameField);
			String copyUsername = getProperty(copy, usernameField);
			assertEquals(
					"Task 9: After copying a user, the usernames [" + userUsername + "] and [" + copyUsername + "] " +
							"are different",
					userUsername,
					copyUsername);

			Field passwordField = getDeclaredFieldByColumnName(userClass, "password");
			String userPassword = getProperty(user, passwordField);
			String copyPassword = getProperty(copy, passwordField);
			assertEquals(
					"Task 9: After copying a user, the passwords [" + userPassword + "] and [" + copyPassword + "] " +
							"are different",
					userPassword,
					copyPassword);
		} catch (Exception e) {
			fail("Task 9: `User`'s copy constructor threw an exception: " + e);
		}
	}

	@Test
	public void task_10() throws Exception {
		// add custom UserDetailsService
		task_1();
		assertUserStructure();
		assertUserRepositoryStructure();
		assertDatabaseContents();
		assertUserAuthorityStructure();

		Class<?> userDetailsManagerClass = assertClass("Task 10", "io.jzheaux.springsecurity.resolutions.UserRepositoryDetailsService");
		assertTrue(
				"Task 2: Couldn't find a `UserDetailsService` of type `io.jzheaux.springsecurity.resolutions.UserRepositoryDetailsService` in the application context. " +
						"Make sure that you are exposing a `@Bean` of that type.",
				this.context.getBeanNamesForType(userDetailsManagerClass).length > 0);

		Class<?> userRepositoryClass = assertClass("Task 10", "io.jzheaux.springsecurity.resolutions.UserRepository");
		Field userRepositoryField = getDeclaredFieldByType(userDetailsManagerClass, userRepositoryClass);
		assertNotNull(
				"Task 10: For this exercise make sure that your custom UserDetailsService implementation is delegating to " +
						"a `UserRepository` instance",
				userRepositoryField);

		Class<?> userClass = assertClass("Task 10", "io.jzheaux.springsecurity.resolutions.User");
		Class<?> userDetailsClass = assertClass("Task 10", "org.springframework.security.core.userdetails.UserDetails");
		Object user = new SpringSecurityClasspathGuard(this.context).getUser("user");

		assertTrue(
				"Task 10: The object returned from a custom `UserDetailsService` should be castable to your custom " +
						"`User` type.",
				userClass.isAssignableFrom(user.getClass()));

		assertTrue(
				"Task 10: The object returned from a custom `UserDetailsService` must be castable to `UserDetails`",
				userClass.isAssignableFrom(userDetailsClass.getClass()));

		MvcResult result = this.mvc.perform(get("/resolutions")
				.with(httpBasic("user", "password")))
				.andReturn();

		assertEquals(
				"Task 10: The `/resolutions` response failed to authorize user/password as the username and password. " +
						"Make sure that your custom `UserDetailsService` is wired with a password of `password`.",
				result.getResponse().getStatus(), 200);
	}

	private Class<?> assertClass(String task, String className) throws Exception {
		try {
			return Class.forName(className);
		} catch (Exception e) {
			fail(task + ": Tried to load " + className + " and failed with exception: " + e + ". " +
					"Make sure that this class is in the expected package.");
			throw e;
		}
	}

	private void assertUserStructure() throws Exception {
		Class<?> userClass = assertClass("Task 3", "io.jzheaux.springsecurity.resolutions.User");
		Entity userEntity = userClass.getAnnotation(Entity.class);

		assertTrue(
				"Task 3: Since you are going to be using JdbcUserDetailsManager to retrieve users in an upcoming step, " +
						"the Users class needs to be annotated with @javax.persistence.Entity(name=\"users\") since that's the table name that the " +
						"manager expects",
				userEntity != null && "users".equals(userEntity.name()));

		Field usernameField = getDeclaredFieldByName(userClass, "username");
		Field usernameColumnField = getDeclaredFieldByColumnName(userClass, "username");

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a field named `username` or a field annotated with `@Column(name=\"username\")`.",
				usernameColumnField);

		assertEquals(
				"Task 3: Make sure that there is only one field acting as the `username` column. " +
						"The easiest way to do this is to have a `username` field with a default `@Column` annotation.",
				usernameField, usernameColumnField);

		Field passwordField = getDeclaredFieldByName(userClass, "password");
		Field passwordColumnField = getDeclaredFieldByColumnName(userClass, "password");

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a field named `password` or a field annotated with `@Column(name=\"username\")`.",
				passwordColumnField);

		assertEquals(
				"Task 3: Make sure that there is only one field acting as the `password` column. " +
						"The easiest way to do this is to have a `password` field with a default `@Column` annotation.",
				passwordField, passwordColumnField);

		Field enabledField = getDeclaredFieldByName(userClass, "enabled");
		Field enabledColumnField = getDeclaredFieldByColumnName(userClass, "enabled");

		assertNotNull(
				"Task 3: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `Users` class needs a field named `enabled` or a field annotated with `@Column(name=\"username\")`.",
				enabledColumnField);

		assertEquals(
				"Task 3: Make sure that there is only one field acting as the `enabled` column. " +
						"The easiest way to do this is to have a `enabled` field with a default `@Column` annotation.",
				enabledField, enabledColumnField);
	}

	private void assertUserRepositoryStructure() throws Exception {
		Class<?> userRepositoryClass = assertClass("Task 4", "io.jzheaux.springsecurity.resolutions.UserRepository");
		Map<String, Type> userRepositoryTypes = Stream.of(userRepositoryClass.getGenericInterfaces())
				.collect(Collectors.toMap(t -> ((ParameterizedType) t).getRawType().getTypeName(), Function.identity()));
		ParameterizedType crudRepositoryType = (ParameterizedType)
				userRepositoryTypes.get(CrudRepository.class.getName());

		assertNotNull(
				"Task 4: Make sure that your `UserRepository` is extending " + CrudRepository.class.getName(),
				userRepositoryTypes.containsKey(CrudRepository.class.getName()));

		Type[] crudRepositoryTypeParameters = crudRepositoryType.getActualTypeArguments();
		assertEquals(
				"Task 4: Make sure that the first type parameter for `UserRepository` is for your `User` class",
				"io.jzheaux.springsecurity.resolutions.User", crudRepositoryTypeParameters[0].getTypeName());

		assertNotNull(
				"Task 4: Make sure that your `UserRepository` is annotated with " + Repository.class,
				userRepositoryClass.getAnnotation(Repository.class));
	}

	private void assertDatabaseContents() throws Exception {
		Class<?> userRepositoryClass = assertClass("Task 5", "io.jzheaux.springsecurity.resolutions.UserRepository");
		Object userRepositoryBean = this.context.getBean(userRepositoryClass);

		Method userRepositoryFindAllMethod = userRepositoryClass.getMethod("findAll");
		Iterable<?> users = (Iterable) userRepositoryFindAllMethod.invoke(userRepositoryBean);
		Map<String, Object> usersByUsername = StreamSupport.stream(users.spliterator(), false)
				.collect(Collectors.toMap(o -> getProperty(o, "username"), Function.identity()));

		Object user = usersByUsername.get("user");
		assertNotNull(
				"Task 5: To ensure that future tests work, make sure that that `UserRepository` has at least a user " +
						"whose username is `user`",
				user);

		SpringSecurityClasspathGuard guard = new SpringSecurityClasspathGuard(this.context);
		String storedPassword = getProperty(user, "password");
		assertTrue(
				"Task 5: Make sure that you are using the default password encoder to encode the user's password " +
						"before persisting. The default password encoder is `PasswordEncoderFactories.createDelegatingPasswordEncoder`",
				guard.matches("password", storedPassword));
	}


	private void assertUserAuthorityStructure() throws Exception {
		Class<?> authorityClass = assertClass("Task 7", "io.jzheaux.springsecurity.resolutions.UserAuthority");
		Class<?> userClass = assertClass("Task 7", "io.jzheaux.springsecurity.resolutions.User");
		Entity authorityEntity = authorityClass.getAnnotation(Entity.class);

		assertTrue(
				"Task 7: Since you are using `JdbcUserDetailsManager` to retrieve users, " +
						"the `UserAuthority` class needs to be annotated with `@Entity(name=\"authorities\")` since " +
						"that's the table name that the manager expects by default",
				authorityEntity != null && "authorities".equals(authorityEntity.name()));

		Field authorityField = getDeclaredFieldByName(authorityClass, "authority");
		Field authorityColumnField = getDeclaredFieldByColumnName(authorityClass, "authority");

		assertNotNull(
				"Task 7: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `UserAuthority` class needs a field named `authority` or a field annotated with `@Column(name=\"authority\")`.",
				authorityColumnField);

		assertEquals(
				"Task 7: Make sure that there is only one field acting as the `username` column. " +
						"The easiest way to do this is to have a `username` field with a default `@Column` annotation.",
				authorityField, authorityColumnField);

		Field userField = getDeclaredFieldByType(authorityClass, userClass);
		Field usernameColumnField = getDeclaredFieldByColumnName(authorityClass, "username");

		assertNotNull(
				"Task 7: Since you are going to be using `JdbcUserDetailsManager` to retrieve users in an upcoming step, " +
						"the `UserAuthority` class needs a `username` column. JPA can do this with the `@JoinColumn` annotation on a " +
						"field of type `User`.",
				usernameColumnField);

		assertEquals(
				"Task 7: Make sure that there is only one field acting as the `username` column. " +
						"The easiest way to do this is to have a field of type `User` with a `@JoinColumn` " +
						"specifying a `name` and `referencedColumnName` of `username`.",
				userField, usernameColumnField);

		assertNotNull(
				"Task 7: Make sure that the `User` field is annotated with `@ManyToOne`",
				userField.getAnnotation(ManyToOne.class));

		Field userAuthoritiesField = getDeclaredFieldHavingAnnotation(userClass, OneToMany.class);
		assertNotNull(
				"Task 7: Make sure that you've updated `User` to declare its bi-directional relationship to `UserAuthority`. " +
						"There should be a field annotated with `@OneToMany` with a collection of type `UserAuthority`.",
				userAuthoritiesField);

		Object userInstance = userClass.newInstance();
		try {
			Method m = userInstance.getClass().getDeclaredMethod("grantAuthority", String.class);
			m.setAccessible(true);
			m.invoke(userInstance, "READ");
		} catch (Exception e) {
			fail("Task 7: Tried to grant an authority, but experienced an error: " + e);
		}

		try {
			Collection<?> authorities = (Collection<?>) userAuthoritiesField.get(userInstance);
			assertTrue(
					"Task 7: After granting an authority, the authorities list is still empty. Make sure you are adding " +
							"an authority to your `User`'s authority list when `grantAuthority` is called.",
					authorities.size() > 0);

			Optional<?> hasRoleUser = authorities.stream()
					.filter(a -> "READ".equals(getProperty(a, authorityField)))
					.findFirst();
			assertTrue(
					"Task 7: After granting an authority, the authorities list does not have a `UserAuthority` whose value " +
							"is `READ`. Make sure you are setting the authority's value to be what is passed in to " +
							"`grantAuthority`",
					hasRoleUser.isPresent());

			Object userAuthority = hasRoleUser.get();
			Object user = getProperty(userAuthority, userField);
			assertEquals(
					"Task 7: Make sure that the `User` stored in `UserAuthority` matches the `User` instance on which " +
							"`grantAuthority` was called.",
					userInstance, user);
		} catch (Exception e) {
			fail(
					"Task 7: Make sure that the authorities property in `User` is called `userAuthorities`. While not strictly " +
							"necessary, with simplify future steps.");
		}
	}

	private Object findUserWithAuthority(String authority) throws Exception {
		Class<?> userRepositoryClass = assertClass("Task 5", "io.jzheaux.springsecurity.resolutions.UserRepository");
		Object userRepositoryBean = this.context.getBean(userRepositoryClass);

		Method userRepositoryFindAllMethod = userRepositoryClass.getMethod("findAll");
		Iterable<?> users = (Iterable) userRepositoryFindAllMethod.invoke(userRepositoryBean);

		for (Object user : users) {
			Field authoritiesField = getDeclaredFieldHavingAnnotation(user.getClass(), OneToMany.class);
			Collection<?> userAuthorities = getProperty(user, authoritiesField);
			for (Object userAuthority : userAuthorities) {
				Field authorityField = getDeclaredFieldByColumnName(userAuthority.getClass(), "authority");
				Object value = getProperty(userAuthority, authorityField);
				if (authority.equals(value)) {
					return user;
				}
			}
		}

		return null;
	}

	private Field getDeclaredFieldByType(Class<?> type, Class<?> fieldType) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getType() == fieldType)
				.findFirst().orElse(null);
	}

	private Field getDeclaredFieldByName(Class<?> type, String name) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getName().equals(name))
				.findFirst().orElse(null);
	}

	private Field getDeclaredFieldByColumnName(Class<?> type, String columnName) {
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

	private Field getDeclaredFieldHavingAnnotation(Class<?> type, Class<? extends Annotation> annotation) {
		return Stream.of(type.getDeclaredFields())
				.filter(f -> f.getAnnotation(annotation) != null)
				.findFirst().orElse(null);
	}

	private Constructor<?> getConstructor(Class<?> type, Class<?>... parameterTypes) {
		try {
			return type.getConstructor(parameterTypes);
		} catch (Exception e) {
			return null;
		}
	}

	private <T> T getProperty(Object o, String property) {
		try {
			return getProperty(o, o.getClass().getDeclaredField(property));
		} catch (Exception e) {
			throw new RuntimeException("Tried to get " + property + " from " + o, e);
		}
	}

	private <T> T getProperty(Object o, Field field) {
		try {
			field.setAccessible(true);
			return (T) field.get(o);
		} catch (Exception e) {
			throw new RuntimeException("Tried to get " + field + " from " + o, e);
		}
	}

	// prevents Spring Security classes from loading, since the first task checks if Spring Security
	// is on the classpath and we want the assertion to message the user as opposed to getting a general
	// classloader failure
	private static class SpringSecurityClasspathGuard {

		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		UserDetailsService service;

		public SpringSecurityClasspathGuard(ApplicationContext context) {
			this.service = context.getBean(UserDetailsService.class);
		}

		boolean matches(String password, String encoded) {
			return this.encoder.matches(password, encoded);
		}

		Collection<String> getUserAuthorities(String username) {
			UserDetails details = this.service.loadUserByUsername(username);
			return details.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority)
					.collect(Collectors.toList());
		}

		Object getUser(String username) {
			return this.service.loadUserByUsername(username);
		}
	}
}
