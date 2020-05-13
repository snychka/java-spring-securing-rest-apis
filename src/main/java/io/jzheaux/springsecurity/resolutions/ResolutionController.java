package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.transaction.Transactional;
import java.util.Optional;
import java.util.UUID;

@RestController
public class ResolutionController {
	private final ResolutionRepository resolutions;

	public ResolutionController(ResolutionRepository resolutions) {
		this.resolutions = resolutions;
	}

	@PreAuthorize("hasAuthority('resolution:read')")
	@PostFilter("@post.filter(#root)")
	@GetMapping("/resolutions")
	public Iterable<Resolution> read() {
		return this.resolutions.findAll();
	}

	@PreAuthorize("hasAuthority('resolution:read')")
	@PostAuthorize("@post.authorize(#root)")
	@GetMapping("/resolution/{id}")
	public Optional<Resolution> read(@PathVariable("id") UUID id) {
		return this.resolutions.findById(id);
	}

	@PreAuthorize("hasAuthority('resolution:write')")
	@PostMapping("/resolution")
	public Resolution make(@CurrentUsername String owner, @RequestBody String text) {
		Resolution resolution = new Resolution(text, owner);
		return this.resolutions.save(resolution);
	}

	@PreAuthorize("hasAuthority('resolution:write')")
	@PostAuthorize("@post.authorize(#root)")
	@PutMapping(path="/resolution/{id}/revise")
	@Transactional
	public Optional<Resolution> revise(@PathVariable("id") UUID id, @RequestBody String text) {
		this.resolutions.revise(id, text);
		return read(id);
	}

	@PreAuthorize("hasAuthority('resolution:write')")
	@PostAuthorize("@post.authorize(#root)")
	@PutMapping("/resolution/{id}/complete")
	@Transactional
	public Optional<Resolution> complete(@PathVariable("id") UUID id) {
		this.resolutions.complete(id);
		return read(id);
	}
}
