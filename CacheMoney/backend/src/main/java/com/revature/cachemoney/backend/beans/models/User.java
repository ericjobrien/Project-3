package com.revature.cachemoney.backend.beans.models;

import javax.persistence.*;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Model containing information regarding a User account.
 */
@Getter
@Setter
@ToString
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Integer userId;

	@Column(name = "first_name", nullable = false)
	private String firstName;

	@Column(name = "last_name", nullable = false)
	private String lastName;

	@Column(name = "email", unique = true, nullable = false)
	private String email;

	@Column(name = "username", unique = true, nullable = false)
	private String username;

	@Column(name = "password", nullable = false)
	private String password;

	// TODO: trying 2fa
	@Column(name = "secret")
	private String secret;

	public User(String firstName, String lastName, String email, String password, String username, String secret) {
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
		this.password = password;
		this.username = username;
		this.secret = secret;
	}
}
