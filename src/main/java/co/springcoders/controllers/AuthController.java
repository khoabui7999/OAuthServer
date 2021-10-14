package co.springcoders.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class AuthController {
    @GetMapping(value = "/validatetoken")
    public boolean validateToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        return token.isBlank() ? false : true;
    }
}
