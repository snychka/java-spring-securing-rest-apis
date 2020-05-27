package io.jzheaux.springsecurity.resolutions;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Optional;

@Service
public class UserService {
	private final WebClient web;

	public UserService(WebClient.Builder web) {
		this.web = web.build();
	}
	public Optional<String> getFullName(String username) {

		String fullName = this.web.get()
				.uri("/user/{username}/fullName", username)
				.retrieve()
				.bodyToMono(String.class)
				.block();
		return Optional.ofNullable(fullName);
	}
}
