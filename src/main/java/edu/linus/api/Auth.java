package edu.linus.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import edu.linus.api.models.Users;
import jakarta.servlet.http.Cookie;
import org.springframework.core.env.Environment;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class Auth {

    //<- Encryption & Decryption

    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 256;

    public static String encrypt(String strToEncrypt, String secretKey, String salt) {

        try {

            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);

            byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String strToDecrypt, String secretKey, String salt) {

        try {

            byte[] encryptedData = Base64.getDecoder().decode(strToDecrypt);
            byte[] iv = new byte[16];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

            byte[] cipherText = new byte[encryptedData.length - 16];
            System.arraycopy(encryptedData, 16, cipherText, 0, cipherText.length);

            byte[] decryptedText = cipher.doFinal(cipherText);
            return new String(decryptedText, "UTF-8");
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return null;
        }
    }

    //</- Encryption & Decryption

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
                .withExpiresAt(new Date(new Date().getTime() + 24L*60*60*1000)) //24L*60*60*1000 = 1 day
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
                System.out.println("Expired token");
                return null; //Token has expired
            }
            return jwt;
        } catch (JWTVerificationException exception){
            // Invalid signature/claims
            System.out.println("signature/claims");
            return null;
        }
    }

    static DecodedJWT extractTokenFromCookie(Cookie[] cookies, Environment env) {
        if (cookies == null) {
            System.out.println("Cookies is null...");
            return null;
        }
        List<Cookie> filteredCookies = Arrays.stream(cookies).filter(cookie -> cookie.getName().equals("auth-jwt")).toList();

        if (!filteredCookies.isEmpty()) {
            Cookie cookie = filteredCookies.getFirst();
            String token = cookie.getValue();
            DecodedJWT validToken = Auth.validateJWT(token, env);
            return validToken;

        } else {
            System.out.println("No cookie found :(");

            //Not enough cookies
            return null;
        }
    }
}
