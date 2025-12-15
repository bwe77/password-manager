package com.project.password.manager.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/passwords")
@PreAuthorize("isAuthenticated()")
public class PasswordController {
    // GET / - list all passwords
    // GET /{id} - get specific password (decrypted)
    // POST / - create new password
    // PUT /{id} - update password
    // DELETE /{id} - delete password
    // GET /search?q=
    // POST /generate - generate password
    // POST /{id}/check-breach - manual breach check
}