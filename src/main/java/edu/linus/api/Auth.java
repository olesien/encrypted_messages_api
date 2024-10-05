package edu.linus.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.core.env.Environment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

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

    static String generateJWT(Environment env) {
        String secret = env.getProperty("jwtsecret");
        assert secret != null;
        Algorithm algorithm = Algorithm.HMAC256(secret);
        String token = JWT.create()
                .withIssuer("auth0")
                .withExpiresAt(new Date(new Date().getTime() + 60*100*60))
                .sign(algorithm);

        return token;
    }

    static boolean validateJWT(String token, Environment env) {
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
            return !new Date().after(jwt.getExpiresAt()); //Token has expired
        } catch (JWTVerificationException exception){
            // Invalid signature/claims
            return false;
        }
    }
}
