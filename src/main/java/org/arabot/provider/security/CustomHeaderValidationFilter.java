package org.arabot.provider.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;


@Component
public class CustomHeaderValidationFilter implements WebFilter {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 16;
    private static final String USERNAME = "username";


    //Must be added to the properties
    private static final String APPLICATION_SECURITY_HEADER_SECRET_KEY = "application.security.header.secret-key";


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String headerValue = exchange.getRequest().getHeaders().getFirst("X-Encrypted-Claims");

        if (headerValue != null) {

            try {

                Map<String, Object> decodedValue = decryptClaims(headerValue, exchange);

                String username = (String) decodedValue.get(USERNAME);

                if (username != null) {

                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                    context.setAuthentication(authentication);
                    SecurityContextHolder.setContext(context);

                    return chain.filter(exchange);

                } else {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }

            } catch (Exception e) {
                exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                return exchange.getResponse().setComplete();
            }

        } else {
            exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
            return exchange.getResponse().setComplete();
        }
    }

    private Map<String, Object> decryptClaims(String encClaims, ServerWebExchange exchange) throws Exception {

        String[] parts = encClaims.split(":");
        String encodedIv = parts[0];
        String encryptedClaims = parts[1];

        byte[] iv = Base64.getDecoder().decode(encodedIv);
        byte[] encryptedClaimsBytes = Base64.getDecoder().decode(encryptedClaims);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getEncryptKey(exchange), gcmSpec);

        byte[] claimsBytes = cipher.doFinal(encryptedClaimsBytes);
        String claimsJson = new String(claimsBytes, StandardCharsets.UTF_8);

        return new ObjectMapper().readValue(claimsJson, HashMap.class);
    }

    private SecretKeySpec getEncryptKey(ServerWebExchange exchange) {

        String encryptionSecretKey = Objects.requireNonNull(exchange.getApplicationContext()).getEnvironment().getProperty(APPLICATION_SECURITY_HEADER_SECRET_KEY);
        byte[] secretEncryptKeyBytes = encryptionSecretKey.getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];
        System.arraycopy(secretEncryptKeyBytes, 0, key, 0, Math.min(secretEncryptKeyBytes.length, key.length));
        return new SecretKeySpec(key, "AES");
    }

}