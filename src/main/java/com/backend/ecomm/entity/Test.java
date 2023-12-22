package com.backend.ecomm.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tests")
public class Test {
    @Id
    @GeneratedValue
    private int id;
    private String test;
}
