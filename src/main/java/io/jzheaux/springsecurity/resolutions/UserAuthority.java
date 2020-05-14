package io.jzheaux.springsecurity.resolutions;

import javax.persistence.Entity;
import javax.persistence.Column;
import javax.persistence.Id;
import java.util.UUID;

import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

// ...

@Entity(name="authorities")
public class UserAuthority {
    @Id
    UUID id;

    @Column
    String authority;

    @JoinColumn(name="username", referencedColumnName="username")
    @ManyToOne
    User user;

    UserAuthority() {
        this.id = UUID.randomUUID();
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }
}

/*
package io.jzheaux.springsecurity.resolutions;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import java.util.UUID;

@Entity(name="authorities")
public class UserAuthority {
	@Id
	UUID id;

	@JoinColumn(name="username", referencedColumnName="username")
	@ManyToOne
	User user;

	@Column
	String authority;

	UserAuthority() {}

	public UserAuthority(User user, String authority) {
		this.id = UUID.randomUUID();
		this.user = user;
		this.authority = authority;
	}

	public UUID getId() {
		return id;
	}

	public void setId(UUID id) {
		this.id = id;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}
}
 */
