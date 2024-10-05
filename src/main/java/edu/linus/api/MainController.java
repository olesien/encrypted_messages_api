package edu.linus.api;

import edu.linus.api.models.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static edu.linus.api.Auth.generateJWT;
import static edu.linus.api.Auth.hashPassword;

@CrossOrigin(origins = "http://localhost:3000/", maxAge = 3600, allowCredentials = "true")
@RestController // This means that this class is a Controller
@RequestMapping(path="/users") // This means URL's start with /demo (after Application path)
public class MainController {
    private UserRepository userRepository;
    private EncryptedMessagesRepository encryptedMessagesRepository;
    private Environment env;

    MainController(UserRepository userRepository, EncryptedMessagesRepository encryptedMessagesRepository, Environment env) {
        this.userRepository = userRepository;
        this.encryptedMessagesRepository = encryptedMessagesRepository;
        this.env = env;
    }

    Cookie makeSecureCookie (String jwt) {
        Cookie cookie = new Cookie("auth-jwt", jwt);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);  // Turned off for HTTP, but in production mode this would be on
        //cookie.setAttribute("SameSite", "None"); //<- Also turned off for HTTP
        cookie.setPath("/");  // Available to the entire app
        cookie.setMaxAge(7*24*60*60);
        return cookie;
    }

    @PostMapping(path="/register") // Map ONLY POST Requests
    public @ResponseBody ResponseEntity<ApiResponse> register (HttpServletResponse response, @RequestBody RegisterForm registerForm) throws NoSuchAlgorithmException {
        Users n = new Users();
        n.setName(registerForm.getName());
        n.setEmail(registerForm.getEmail());
        n.setPassword(hashPassword(registerForm.getPassword(), env));
        Users savedUser = userRepository.save(n);
        String jwt = generateJWT(env);

        // Set HttpOnly cookie
        response.addCookie(makeSecureCookie(jwt));
        System.out.println("Added cookie");
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success", new UserWithJWT(savedUser.getId(), savedUser.getName(), savedUser.getEmail(), jwt)));
    }

    @PostMapping(path="/login") // Map ONLY POST Requests
    public @ResponseBody ResponseEntity<ApiResponse> login (HttpServletResponse response, @RequestBody LoginForm loginForm) throws NoSuchAlgorithmException {
        String hashedPassword = hashPassword(loginForm.getPassword(), env);

        Optional<Users> user = userRepository.findByEmail(loginForm.getEmail());

        if (user.isPresent()) {
            Users newUser = user.get();
            if (newUser.getPassword().equals(hashedPassword)) {
                //Exists
                String jwt = generateJWT(env);
                // Set HttpOnly cookie
                System.out.println(jwt);
                response.addCookie(makeSecureCookie(jwt));
                System.out.println("Added cookie");

                return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse("Success", new UserWithJWT(newUser.getId(), newUser.getName(), newUser.getEmail(), jwt)));
            } else {
                //403; Passwords do not match
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse("Passwords do not match", null));

            }
        } else {
            //404 not found
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse("Not Found", null));
        }
    }

    @GetMapping(path="/all")
    public @ResponseBody Iterable<Users> getAllUsers() {
        // This returns a JSON or XML with the users
        return userRepository.findAll();
    }

    @GetMapping(path="/encrypted_messages")
    public @ResponseBody Iterable<EncryptedMessages> getEncryptedMessages(HttpServletRequest request) {

        //Get user data here


        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            System.out.println("Cookies is null...");
            return null;
        }

        for (Cookie value : cookies) {
            System.out.println(value.getName());
        }
        List<Cookie> filteredCookies = Arrays.stream(cookies).filter(cookie -> cookie.getName().equals("auth-jwt")).toList();

        if (!filteredCookies.isEmpty()) {
            Cookie cookie = filteredCookies.getFirst();
            String token = cookie.getValue();
            System.out.println(cookie.getName());
            System.out.println(token);
            boolean validToken = Auth.validateJWT(token, env);

            if (validToken) {
                // This returns a JSON or XML with the users
                System.out.println("Token is valid!");
                Users user = new Users();
                user.setId(0);
                return encryptedMessagesRepository.findAllByUser(user);
            }
            System.out.println("Invalid token");
            //Invalid token
            return null;

        } else {
            System.out.println("No cookie found :(");

            //Not enough cookies
            return null;
        }


    }
}