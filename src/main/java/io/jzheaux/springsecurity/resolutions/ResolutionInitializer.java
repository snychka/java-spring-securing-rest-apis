package io.jzheaux.springsecurity.resolutions;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class ResolutionInitializer implements SmartInitializingSingleton {
	@Autowired
	private final UserRepository users;

	private final ResolutionRepository resolutions;

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


		User user = new User();
		user.setUsername("user");
		user.setPassword("{bcrypt}$2a$10$MywQEqdZFNIYnx.Ro/VQ0ulanQAl34B5xVjK2I/SDZNVGS5tHQ08W");

		user.grantAuthority("READ");
		user.grantAuthority("WRITE");

		this.users.save(user);

		User hasread = new User();
		hasread.setUsername("hasread");
		hasread.setPassword("password");
		hasread.grantAuthority("READ");
		this.users.save(hasread);

		User haswrite = new User();
		haswrite.setUsername("haswrite");
		haswrite.setPassword("password");
		haswrite.grantAuthority("WRITE");
		this.users.save(haswrite);
	}
}
