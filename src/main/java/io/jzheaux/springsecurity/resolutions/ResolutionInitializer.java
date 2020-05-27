package io.jzheaux.springsecurity.resolutions;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class ResolutionInitializer implements SmartInitializingSingleton {
	private final ResolutionRepository resolutions;
	private final UserRepository users;

	public ResolutionInitializer(ResolutionRepository resolutions, UserRepository users) {
		this.resolutions = resolutions;
		this.users = users;
	}

	@Override
	public void afterSingletonsInstantiated() {
		UUID joshId = UUID.fromString("219168d2-1da4-4f8a-85d8-95b4377af3c1");
		UUID carolId = UUID.fromString("328167d1-2da3-5f7a-86d7-96b4376af2c0");

		this.resolutions.save(new Resolution("Read War and Peace", joshId));
		this.resolutions.save(new Resolution("Free Solo the Eiffel Tower", joshId));
		this.resolutions.save(new Resolution("Hang Christmas Lights", joshId));

		this.resolutions.save(new Resolution("Run for President", carolId));
		this.resolutions.save(new Resolution("Run a Marathon", carolId));
		this.resolutions.save(new Resolution("Run an Errand", carolId));

		User user = new User("user", "{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe");
		user.grantAuthority("READ");
		this.users.save(user);

		User hasRead = new User("hasread", "{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe");
		hasRead.grantAuthority("READ");
		this.users.save(hasRead);

		User hasWrite = new User("haswrite", "{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe");
		hasWrite.grantAuthority("WRITE");
		this.users.save(hasWrite);
	}
}
