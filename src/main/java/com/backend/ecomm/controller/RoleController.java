package com.backend.ecomm.controller;

import com.backend.ecomm.entity.Role;
import com.backend.ecomm.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class RoleController {
    @Autowired
    private RoleService roleService;

    @PostMapping("/create-role")
    public Role createNewRole(@RequestBody Role role) {
        return roleService.createNewRole(role);
    }
}
