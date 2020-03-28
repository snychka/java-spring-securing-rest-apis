package io.jzheaux.springsecurity.resolutions;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.ClassUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

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
}
