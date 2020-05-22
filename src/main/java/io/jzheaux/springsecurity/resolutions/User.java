
package io.jzheaux.springsecurity.resolutions;

import java.io.Serializable;
import javax.persistence.*;
import java.util.UUID;

import java.util.Collection;
import java.util.Collections;
import java.util.ArrayList;
import javax.persistence.CascadeType;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;

@Entity(name="users")
public class User implements Serializable {

    @Id
    UUID id;

    @Column
    String username;

    @Column(name="full_name")
    String fullName;

    @Column
    String password;

    // STEFAN: needed to make public
    @Column
    public boolean enabled = true;

    // STEFAN: needed to make public
    @OneToMany(fetch=FetchType.EAGER, cascade=CascadeType.ALL)
    public Collection<UserAuthority> userAuthorities = new ArrayList<>();


    User() {}

    public User(User user) {
        this.id = user.id;
        this.username = user.username;
        this.fullName = user.fullName;
        this.password = user.password;
        this.enabled = user.enabled;
        this.userAuthorities = user.userAuthorities;
    }

    public User(String username, String password) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.password = password;
    }

    public Collection<UserAuthority> getUserAuthorities() {
        return Collections.unmodifiableCollection(this.userAuthorities);
    }

    public void grantAuthority(String authority) {
        UserAuthority userAuthority = new UserAuthority(this, authority);
        this.userAuthorities.add(userAuthority);
        /*UserAuthority userAuthority = new UserAuthority();
        userAuthority.setUser(this);
        userAuthority.setAuthority(authority);
        this.userAuthorities.add(userAuthority);

         */
    }

    public void setUsername(String username) {
        this.username = username;
    }


    public void setPassword(String password) {
        this.password = password;
    }

    // STEFAN: needed to create
    public String getPassword() {
        return this.password;
    }

    // STEFAN: needed to create
    public String getUsername() {
        return this.username;
    }

    // STEFAN: needed to create
    public boolean isEnabled() {
        return this.enabled;
    }



    public UUID getId() {
        return id;
    }


    public void setFullName(String u) {
        this.fullName = u;
    }

    public String getFullName() {
        return this.fullName;
    }
}

/*
package io.jzheaux.springsecurity.resolutions;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

@Entity(name="users")
public class User implements Serializable {
    @Id
    UUID id;

    @Column(name="username")
    String username;

    @Column
    String password;

    @Column
    boolean enabled = true;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    Collection<UserAuthority> userAuthorities = new ArrayList<>();

    User() {}

    User(String username, String password) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.password = password;
    }

    User(User user) {
        this.id = user.id;
        this.username = user.username;
        this.password = user.password;
        this.enabled = user.enabled;
        this.userAuthorities = user.userAuthorities;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Collection<UserAuthority> getUserAuthorities() {
        return userAuthorities;
    }

    public void grantAuthority(String authority) {
        this.userAuthorities.add(new UserAuthority(this, authority));
    }
}

 */
