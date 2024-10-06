package edu.linus.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import edu.linus.api.models.Users;
import jakarta.servlet.http.Cookie;
import org.springframework.core.env.Environment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Auth {

    //Maybe switch to: https://www.stubbornjava.com/posts/hashing-passwords-in-java-with-bcrypt ?
    static String hashPassword(String password, Environment env) throws NoSuchAlgorithmException {
        String salt = env.getProperty("salt");

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        assert salt != null;
        md.update(salt.getBytes());

        byte[] hashedBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : hashedBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    static String generateJWT(Environment env, String userId) {
        String secret = env.getProperty("jwtsecret");
        assert secret != null;
        Algorithm algorithm = Algorithm.HMAC256(secret);
        String token = JWT.create()
                .withIssuer("auth0")
                .withSubject(userId)
                .withExpiresAt(new Date(new Date().getTime() + 60*100*60))
                .sign(algorithm);

        return token;
    }

    static DecodedJWT validateJWT(String token, Environment env) {
        String secret = env.getProperty("jwtsecret");
        assert secret != null;
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    // specify any specific claim validations
                    .withIssuer("auth0")
                    // reusable verifier instance
                    .build();

            DecodedJWT jwt = verifier.verify(token);
            if (new Date().after(jwt.getExpiresAt())) {
                return null; //Token has expired
            }
            return jwt;
        } catch (JWTVerificationException exception){
            // Invalid signature/claims
            return null;
        }
    }

    static DecodedJWT extractTokenFromCookie(Cookie[] cookies, Environment env) {
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
            DecodedJWT validToken = Auth.validateJWT(token, env);

            return validToken;

        } else {
            System.out.println("No cookie found :(");

            //Not enough cookies
            return null;
        }
    }
}
