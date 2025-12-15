package com.project.password.manager.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/share")
public class PasswordSharingController {
    // POST / - share password
    // GET /{token} - access shared password
    // DELETE /{shareId} - revoke share
}