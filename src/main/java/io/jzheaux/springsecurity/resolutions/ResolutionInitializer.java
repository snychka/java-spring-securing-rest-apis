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


		this.resolutions.save(new Resolution("Read War and Peace", "user"));
		this.resolutions.save(new Resolution("Free Solo the Eiffel Tower", "user"));
		this.resolutions.save(new Resolution("Hang Christmas Lights", "user"));

		User user = new User("user", "{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe");
		user.setFullName("User Userson");
		user.grantAuthority("resolution:read");
		user.grantAuthority("user:read");
		this.users.save(user);

		User hasRead = new User("hasread", "{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe");
		hasRead.setFullName("Reader Readson");
		//hasRead.setFullName("Has Read");
		hasRead.grantAuthority("resolution:read");
		hasRead.grantAuthority("user:read");
		this.users.save(hasRead);

		User hasWrite = new User("haswrite", "{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe");
		hasWrite.setFullName("Writer Writeson");
		//hasWrite.setFullName("Has Write");
		hasWrite.grantAuthority("resolution:write");
		hasWrite.grantAuthority("user:read");
		this.users.save(hasWrite);

		User admin = new User("{bcrypt}$2a$10$bTu5ilpT4YILX8dOWM/05efJnoSlX4ElNnjhNopL9aPoRyUgvXAYa", "admin");
		admin.setFullName("Admin Adminson");
		admin.setUsername("admin");
		admin.setPassword("{bcrypt}$2a$10$bTu5ilpT4YILX8dOWM/05efJnoSlX4ElNnjhNopL9aPoRyUgvXAYa");
		admin.grantAuthority("ROLE_ADMIN");
		//admin.grantAuthority("resolution:read");
		//admin.grantAuthority("resolution:write");
		this.users.save(admin);

	}
}
