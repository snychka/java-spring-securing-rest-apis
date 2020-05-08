package io.jzheaux.springsecurity.resolutions;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.data.jpa.repository.Query;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@SpringBootTest
public class Module2_Tests {

	@Autowired
	MockMvc mvc;

	@Autowired
	ApplicationContext context;

	@Autowired
	ResolutionController controller;

	@Autowired
	ResolutionRepository repository;

	@Autowired
	UserDetailsService userDetailsService;

	@Autowired(required = false)
	MethodSecurityInterceptor methodSecurityInterceptor;

	Authentication hasread;
	Authentication haswrite;

	@Before
	public void setup() {
		this.hasread = token("hasread");
		this.haswrite = token("haswrite");
	}

	/**
	 * Add the appropriate Spring Boot starter dependency
	 */
	@Test
	public void task_1() throws Exception {
		// use @PreAuthorize
		assertNotNull(
				"Task 1: Method Security appears to not be turned on yet. Please make sure that " +
						"you've added `@EnableGlobalMethodSecurity(prePostEnabled = true)` to the application.",
				this.methodSecurityInterceptor);
		DelegatingMethodSecurityMetadataSource delegating = (DelegatingMethodSecurityMetadataSource) this.methodSecurityInterceptor.getSecurityMetadataSource();

		assertTrue(
				"Task 1: Make sure you've configured method security for the `@Pre` and `@PostAuthorize` annotations " +
						"by setting the `prePostEnabled` attribute to `true`",
				delegating.getMethodSecurityMetadataSources().stream()
						.anyMatch(PrePostAnnotationSecurityMetadataSource.class::isInstance));

		Method readMethod = ResolutionController.class.getDeclaredMethod("read", User.class);
		PreAuthorize readPreAuthorize = readMethod.getAnnotation(PreAuthorize.class);
		assertNotNull(
				"Task 1: Please add the `@PreAuthorize` annotation to the `ResolutionController#read` method.",
				readPreAuthorize);

		try {
			SecurityContextHolder.getContext().setAuthentication(this.hasread);
			this.controller.read((User) this.hasread.getPrincipal());
		} catch (AccessDeniedException e) {
			fail("Task 1: Your `@PreAuthorize` annotation evaluated to `false` when it was " +
					"given a user with a `READ` permission. Double check your expression; it " +
					"should look something like `@PreAuthorize('READ')`");
		} finally {
			SecurityContextHolder.clearContext();
		}

		try {
			SecurityContextHolder.getContext().setAuthentication(this.haswrite);
			this.controller.read((User) this.haswrite.getPrincipal());
			fail("Task 1: Your `@PreAuthorize` annotation evaluated to `true` when it was " +
					"given a user without a `READ` permission. Double check your expression; it " +
					"should look something like `@PreAuthorize('READ')`");
		} catch (AccessDeniedException expected) {
			// ignore
		} finally {
			SecurityContextHolder.clearContext();
		}

		MvcResult result = this.mvc.perform(get("/resolutions")
			.with(httpBasic("hasread", "password")))
			.andReturn();

		assertNotEquals(
				"Task 1: The `/resolutions` endpoint failed to authenticate with `hasread`/`password`. " +
						"Make sure this username/password is added via your `UserRepository` on startup.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 1: The `/resolutions` endpoint failed to authorize `hasread`/`password`. " +
						"Make sure this username/password is granted the `READ` authority",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 1: The `/resolutions` endpoint failed with a status code of " +
						result.getResponse().getStatus(),
				200, result.getResponse().getStatus());
	}

	@Test
	public void task_2() throws Exception {
		// use post filter
		task_1();
		UUID hasReadUuid = new ReflectedUser((User) this.hasread.getPrincipal()).getId();
		UUID hasWriteUuid = new ReflectedUser((User) this.haswrite.getPrincipal()).getId();

		this.repository.save(new Resolution("has read test", hasReadUuid));
		this.repository.save(new Resolution("has write test", hasWriteUuid));

		Method readMethod = ResolutionController.class.getDeclaredMethod("read", User.class);
		PostFilter readPostFilter = readMethod.getAnnotation(PostFilter.class);
		assertNotNull(
				"Task 2: Please add the `@PostFilter` annotation to the `read()` method.",
				readPostFilter);

		SecurityContextHolder.getContext().setAuthentication(this.hasread);
		try {
			List<Resolution> resolutions = this.controller.read((User) this.hasread.getPrincipal());
			assertFalse(
					"Task 2: Calling `ResolutionController#read()` returned no results. " +
							"Make sure that your filter is keeping records whose owner matches the logged in user.",
					resolutions.isEmpty());
			for (Resolution resolution : resolutions) {
				assertEquals(
						"Task 2: One of the resolutions returned from RepositoryController#read() " +
								"did not belong to the logged-in user. Make sure that your `@PostFilter` " +
								"annotation is checking that the resolution's owner id matches the logged in user's id.",
						hasReadUuid, resolution.getOwner());
			}
		} finally {
			SecurityContextHolder.clearContext();
		}
	}

	@Test
	public void task_3() throws Exception {
		// use @PostAuthorize
		task_2();
		Method readMethod = ResolutionController.class.getDeclaredMethod("read", UUID.class);
		PostAuthorize readPostAuthorize = readMethod.getAnnotation(PostAuthorize.class);
		assertNotNull(
				"Task 3: Please add the `@PostAuthorize` annotation to the `ResolutionController#read(UUID)` method.",
				readPostAuthorize);

		UUID hasReadUuid = new ReflectedUser((User) this.hasread.getPrincipal()).getId();
		UUID hasWriteUuid = new ReflectedUser((User) this.haswrite.getPrincipal()).getId();
		Resolution hasReadResolution = this.repository.findByOwner(hasReadUuid).iterator().next();
		Resolution hasWriteResolution = this.repository.findByOwner(hasWriteUuid).iterator().next();

		SecurityContextHolder.getContext().setAuthentication(this.hasread);
		try {
			this.controller.read(hasReadResolution.getId());
		} catch (AccessDeniedException e) {
			fail("Task 3: The `/resolution/{id}` endpoint failed to authorize the `hasread` user to read a resolution " +
					"that belonged to them. Please double-check your `@PostAuthorize` expression.");
		} finally {
			SecurityContextHolder.clearContext();
		}

		SecurityContextHolder.getContext().setAuthentication(this.hasread);
		try {
			this.controller.read(hasWriteResolution.getId());
			fail("Task 3: The `/resolution/{id}` endpoint authorized the `hasread` user to read a resolution " +
					"that didn't belonged to them. Please double-check your `@PostAuthorize` expression.");
		} catch (AccessDeniedException expected) {
			// ignore
		} finally {
			SecurityContextHolder.clearContext();
		}

		MvcResult result = this.mvc.perform(get("/resolution/" + hasReadResolution.getId())
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertNotEquals(
				"Task 1: The `/resolution/{id}` endpoint failed to authenticate with `hasread`/`password`. " +
						"Make sure this username/password is added via your `UserRepository` on startup.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 1: The `/resolution/{id}` endpoint failed to authorize `hasread`/`password`. " +
						"Make sure this username/password is granted the `READ` authority.",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 1: The `/resolution/{id}` endpoint failed with a status code of " +
						result.getResponse().getStatus(),
				200, result.getResponse().getStatus());
	}

	@Test
	public void task_4() throws Exception {
		task_3();

		Method reviseMethod = ResolutionRepository.class.getDeclaredMethod("revise", UUID.class, String.class);
		Query reviseQuery = reviseMethod.getAnnotation(Query.class);
		assertNotNull(
				"Task 4: Please restore the `@Query` annotation to the `ResolutionRepository#revise(UUID, String)` method.",
				reviseQuery);

		assertTrue(
				"Task 4: Use the `?#{principal.id}` expression to change the query and ensure that no update is performed unless the " +
						"resolution belongs to the logged-in user.",
				reviseQuery.value().contains("?#{principal"));


		UUID hasReadUuid = new ReflectedUser((User) this.hasread.getPrincipal()).getId();
		UUID hasWriteUuid = new ReflectedUser((User) this.haswrite.getPrincipal()).getId();
		Resolution hasReadResolution = this.repository.findByOwner(hasReadUuid).iterator().next();
		Resolution hasWriteResolution = this.repository.findByOwner(hasWriteUuid).iterator().next();

		SecurityContextHolder.getContext().setAuthentication(this.haswrite);
		try {
			this.controller.revise(hasWriteResolution.getId(), hasWriteResolution.getText() + " (revised)");
		} catch (AccessDeniedException e) {
			fail("Task 4: The `/resolution/{id}` PUT endpoint failed to authorize the `haswrite` user to read a resolution " +
					"that belonged to them. Please double-check your `@Query` expression.");
		} finally {
			SecurityContextHolder.clearContext();
		}

		SecurityContextHolder.getContext().setAuthentication(this.haswrite);
		try {
			this.controller.revise(hasReadResolution.getId(), hasReadResolution.getText() + " (revised)");
			fail("Task 4: The `/resolution/{id}` endpoint authorized the `hasread` user to read a resolution " +
					"that didn't belonged to them. Please double-check your `@PostAuthorize` expression.");
		} catch (AccessDeniedException expected) {
			// ignore
		} finally {
			SecurityContextHolder.clearContext();
		}
	}

	@Test
	public void task_5() throws Exception {
		// add custom authorization expression
	}

	@Test
	public void task_6() throws Exception {
		// add custom authorization rule
	}

	Authentication token(String username) {
		UserDetails details = this.userDetailsService.loadUserByUsername(username);
		return new TestingAuthenticationToken(details, details.getPassword(),
				new ArrayList<>(details.getAuthorities()));
	}
}
