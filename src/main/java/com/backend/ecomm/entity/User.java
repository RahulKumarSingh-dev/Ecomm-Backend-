package com.backend.ecomm.entity;

import jakarta.annotation.Nonnull;
import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Entity
@Table(uniqueConstraints = @UniqueConstraint(columnNames = "email"))
public class User {

    @Id
    @GeneratedValue
    private int id;
    private String name;

    private String email;

    private String password;

    private String forgotPasswordToken;

    private Date forgotPasswordExpiry;
    @Column(nullable = false, updatable = false)


    @Temporal(TemporalType.TIMESTAMP)
    private Date createdAt=new Date();

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "USER_ROLE", joinColumns = {@JoinColumn(name = "USER_ID")}, inverseJoinColumns = {@JoinColumn(name = "ROLE_ID")})
    private Set<Role> role;

    private String refreshToken;

//   TODO: private Photo photo;


}

/*

name
email
password
role
photo 
{ id, secure url }
resetPasswordToken
resetPasswordExpiry
createdAt
 */