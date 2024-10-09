package edu.linus.api;

import com.auth0.jwt.interfaces.DecodedJWT;
import edu.linus.api.models.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import static edu.linus.api.Auth.*;

@CrossOrigin(origins = "http://localhost:3000/", maxAge = 3600, allowCredentials = "true", allowPrivateNetwork = "true")
@RestController // This means that this class is a Controller
@RequestMapping(path="/users") // This means URL's start with /demo (after Application path)
public class MainController {
    private final UserRepository userRepository;
    private final EncryptedMessagesRepository encryptedMessagesRepository;
    private final Environment env;

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
    public @ResponseBody ResponseEntity<ApiResponse<Object>> register (HttpServletResponse response, @RequestBody RegisterForm registerForm) throws NoSuchAlgorithmException {
        Users n = new Users();
        n.setName(registerForm.getName());
        n.setEmail(registerForm.getEmail());
        n.setPassword(hashPassword(registerForm.getPassword(), env));
        Users savedUser = userRepository.save(n);
        String jwt = generateJWT(env, savedUser.getId().toString());

        // Set HttpOnly cookie
        response.addCookie(makeSecureCookie(jwt));
        System.out.println("Added cookie");
        return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse<>("Success", new UserWithJWT(savedUser.getId(), savedUser.getName(), savedUser.getEmail(), jwt)));
    }

    @PostMapping(path="/login") // Map ONLY POST Requests
    public @ResponseBody ResponseEntity<ApiResponse<Object>> login (HttpServletResponse response, @RequestBody LoginForm loginForm) throws NoSuchAlgorithmException {
        String hashedPassword = hashPassword(loginForm.getPassword(), env);

        Optional<Users> user = userRepository.findByEmail(loginForm.getEmail());

        if (user.isPresent()) {
            Users newUser = user.get();
            if (newUser.getPassword().equals(hashedPassword)) {
                //Exists
                String jwt = generateJWT(env, newUser.getId().toString());
                // Set HttpOnly cookie
                System.out.println(jwt);
                response.addCookie(makeSecureCookie(jwt));
                System.out.println("Added cookie");

                return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse<>("Success", new UserWithJWT(newUser.getId(), newUser.getName(), newUser.getEmail(), jwt)));
            } else {
                //403; Passwords do not match
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>("Passwords do not match", null));

            }
        } else {
            //404 not found
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("Not Found", null));
        }
    }

//    @GetMapping(path="/all")
//    public @ResponseBody Iterable<Users> getAllUsers() {
//        // This returns a JSON or XML with the users
//        return userRepository.findAll();
//    }

    @GetMapping(path="/encrypted_messages")
    public @ResponseBody ResponseEntity<ApiResponse<Iterable<EncryptedMessages>>> getEncryptedMessages(HttpServletRequest request) {

        //Get user data here
        String salt = env.getProperty("salt");
        String encryptionSecret = env.getProperty("encryptionsecret");

        DecodedJWT validToken = Auth.extractTokenFromCookie(request.getCookies(), env);
        if (validToken != null) {
            Optional<Users> user = userRepository.findById(Integer.valueOf(validToken.getSubject()));
            //User not found
            if (user.isPresent()) {
                Users validUser = user.get();
                return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse<>("Success!", encryptedMessagesRepository.findAllByUserOrderByIdAsc(validUser).stream().map(message -> {
                    message.setTitle(decrypt(message.getTitle(), salt, encryptionSecret));
                    message.setMessage(decrypt(message.getMessage(), salt, encryptionSecret));
                    message.setUser(null); //Prevent leak of encrypted password
                    return message;
                }).toList()));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("User Not Found", null));
            }


        }
        //Invalid token
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>("Invalid Token", null));

    }

    @PostMapping("/encrypted_message")
    public @ResponseBody ResponseEntity<ApiResponse<Object>> addEncryptedMessage(HttpServletRequest request, @RequestBody EncryptedMessageForm encryptedMessageForm) {
        DecodedJWT validToken = Auth.extractTokenFromCookie(request.getCookies(), env);
        String salt = env.getProperty("salt");
        String encryptionSecret = env.getProperty("encryptionsecret");
        if (validToken != null) {
            Optional<Users> user = userRepository.findById(Integer.valueOf(validToken.getSubject()));
            if (user.isPresent()) {
                Users validUser = user.get();
                EncryptedMessages encryptedMessage = new EncryptedMessages();
                encryptedMessage.setTitle(encrypt(encryptedMessageForm.getTitle(), salt, encryptionSecret));
                encryptedMessage.setMessage(encrypt(encryptedMessageForm.getMessage(), salt, encryptionSecret));
                encryptedMessage.setUser(validUser);
                return ResponseEntity.status(HttpStatus.CREATED).body(new ApiResponse<>("Success!", encryptedMessagesRepository.save(encryptedMessage)));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("User Not Found", null));
            }
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>("Invalid Token", null));
    }

    @PutMapping("/encrypted_message")
    public @ResponseBody ResponseEntity<ApiResponse<Object>> editEncryptedMessage(HttpServletRequest request, @RequestBody EncryptedMessages encryptedMessage) {
        DecodedJWT validToken = Auth.extractTokenFromCookie(request.getCookies(), env);
        String salt = env.getProperty("salt");
        String encryptionSecret = env.getProperty("encryptionsecret");
        if (validToken != null) {
            Optional<Users> user = userRepository.findById(Integer.valueOf(validToken.getSubject()));
            if (user.isPresent()) {
                Users validUser = user.get();
                encryptedMessage.setUser(validUser); //Make sure a user can't fake as another user.
                encryptedMessage.setTitle(encrypt(encryptedMessage.getTitle(), salt, encryptionSecret));
                encryptedMessage.setMessage(encrypt(encryptedMessage.getMessage(), salt, encryptionSecret));
                return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse<>("Success!", encryptedMessagesRepository.save(encryptedMessage)));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("User Not Found", null));
            }
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>("Invalid Token", null));
    }

    @DeleteMapping("/encrypted_message/delete/{id}")
    public @ResponseBody ResponseEntity<ApiResponse<Object>> removeEncryptedMessage(HttpServletRequest request, @PathVariable("id") int messageId) {
        DecodedJWT validToken = Auth.extractTokenFromCookie(request.getCookies(), env);
        if (validToken != null) {
            Optional<Users> user = userRepository.findById(Integer.valueOf(validToken.getSubject()));
            if (user.isPresent()) {
                Users validUser = user.get();
                Optional<EncryptedMessages> encryptedMessage = encryptedMessagesRepository.findByIdAndUser(messageId, validUser);
                if (encryptedMessage.isPresent()) {
                    encryptedMessagesRepository.delete(encryptedMessage.get());
                    return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse<>("Success!", null));
                } else {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("Message Not Found", null));
                }

            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("User Not Found", null));
            }
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>("Invalid Token", null));
    }

    @DeleteMapping("/deleteaccount")
    public @ResponseBody ResponseEntity<ApiResponse<Object>> deleteUser(HttpServletRequest request) {
        DecodedJWT validToken = Auth.extractTokenFromCookie(request.getCookies(), env);
        if (validToken != null) {
            Optional<Users> user = userRepository.findById(Integer.valueOf(validToken.getSubject()));
            if (user.isPresent()) {
                Users validUser = user.get();
                encryptedMessagesRepository.deleteAllByUserId(validUser.getId());
                userRepository.delete(validUser);
                return ResponseEntity.status(HttpStatus.OK).body(new ApiResponse<>("Success!", null));

            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>("User Not Found", null));
            }
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiResponse<>("Invalid Token", null));
    }
}