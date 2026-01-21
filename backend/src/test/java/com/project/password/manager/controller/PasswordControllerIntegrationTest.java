// package com.project.password.manager.controller;

// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.test.web.servlet.MockMvc;

// @SpringBootTest
// @AutoConfigureMockMvc   
// public class PasswordControllerIntegrationTest {

//     @Autowired
//     private MockMvc mockMvc;

//     @Test
//     public void shouldCreatePassword() throws Exception {
//         // Integration test for creating a password entry
//         // Implement test logic here
//         String token = "<JWT_TOKEN>";

//         mockMvc.perform(post("/api/passwords"))
//             .header("Authorization", "Bearer " + token)
//             .header("X-Master-Password", "test-master-password")
//             .contentType(MediaType.APPLICATION_JSON)
//             .content("{\"siteName\":\"Gmail\",\"password\":\"test123\"}"))
//         .andExpect(status().isCreated())
//         .andExpect(jsonPath("$.siteName").value("Gmail"));
//     }
    
// }
