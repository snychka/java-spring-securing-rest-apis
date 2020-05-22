package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
public class ResolutionController {
	private final ResolutionRepository resolutions;
	private final UserRepository users;

	public ResolutionController(ResolutionRepository resolutions, UserRepository users) {
		this.resolutions = resolutions;
		this.users = users;
	}

	@GetMapping("/resolutions")
	@PreAuthorize("hasAuthority('resolution:read')")
	//@PostFilter("filterObject.owner == authentication.name || hasRole('ADMIN')")
	@PostFilter("@post.filter(#root)")
	@CrossOrigin(allowCredentials = "true") //(maxAge = 0) if locally verifying
	public Iterable<Resolution> read() {
		//return this.resolutions.findAll();
		Iterable<Resolution> resolutions = this.resolutions.findAll();
		for (Resolution resolution : resolutions) {
			String fullName = this.users.findByUsername(resolution.getOwner())
					.map(User::getFullName).orElse("Anonymous");
			resolution.setText(resolution.getText() + ", by " + fullName);
		}
		return resolutions;
	}

	@GetMapping("/resolution/{id}")
	@PreAuthorize("hasAuthority('resolution:read')")
	//@PostAuthorize("returnObject.orElse(null)?.owner == authentication.name || hasRole('ADMIN')")
	@PostAuthorize("@post.authorize(#root)")
	public Optional<Resolution> read(@PathVariable("id") UUID id) {
		return this.resolutions.findById(id);
	}

	@PostMapping("/resolution")
	@PreAuthorize("hasAuthority('resolution:write')")
	public Resolution make(@CurrentUsername String owner, @RequestBody String text) {
		Resolution resolution = new Resolution(text, owner);
		return this.resolutions.save(resolution);
	}

	@PutMapping(path="/resolution/{id}/revise")
	@PreAuthorize("hasAuthority('resolution:write')")
	//@PostAuthorize("returnObject.orElse(null)?.owner == authentication.name")
	@PostAuthorize("@post.authorize(#root)")
	@Transactional
	public Optional<Resolution> revise(@PathVariable("id") UUID id, @RequestBody String text) {
		this.resolutions.revise(id, text);
		return read(id);
	}

	@PutMapping("/resolution/{id}/complete")
	@PreAuthorize("hasAuthority('resolution:write')")
	//@PostAuthorize("returnObject.orElse(null)?.owner == authentication.name")
	@PostAuthorize("@post.authorize(#root)")
	@Transactional
	public Optional<Resolution> complete(@PathVariable("id") UUID id) {
		this.resolutions.complete(id);
		return read(id);
	}
}
