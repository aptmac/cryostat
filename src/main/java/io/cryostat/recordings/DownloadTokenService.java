/*
 * Copyright The Cryostat Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cryostat.recordings;

import java.text.ParseException;
import java.time.Duration;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import io.cryostat.libcryostat.sys.Clock;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Service for generating and validating download tokens. Uses JWT (JSON Web Tokens) with HMAC
 * SHA-256 signing for secure, stateless token generation. Tokens are single-use and tracked in
 * memory to prevent replay attacks.
 */
@ApplicationScoped
public class DownloadTokenService {

    @Inject Logger logger;
    @Inject Clock clock;

    @ConfigProperty(name = "cryostat.recordings.download-token.expiry-duration")
    Duration tokenExpiryDuration;

    @ConfigProperty(name = "cryostat.recordings.download-token.secret")
    String tokenSecret;

    private JWSSigner signer;
    private JWSVerifier verifier;

    // In-memory set to track used token IDs (for single-use enforcement)
    // Key: tokenId, Value: expiration timestamp
    private final ConcurrentHashMap<String, Long> usedTokens = new ConcurrentHashMap<>();

    void onStart(@Observes StartupEvent ev) {
        try {
            // Initialize JWT signer and verifier with the secret key
            byte[] secret = tokenSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (secret.length < 32) {
                throw new IllegalStateException(
                        "Token secret must be at least 32 bytes (256 bits) for HS256");
            }
            this.signer = new MACSigner(secret);
            this.verifier = new MACVerifier(secret);
            logger.infov(
                    "Download token service initialized with expiry duration: {0}",
                    tokenExpiryDuration);
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to initialize JWT signer/verifier", e);
        }
    }

    /**
     * Generate a download token for a recording
     *
     * @param recordingId the ID of the recording (or synthetic ID for archived recordings)
     * @param recordingType the type of recording ("active" or "archived")
     * @param username the username of the user requesting the token
     * @return the generated token information
     */
    public TokenInfo generateToken(Long recordingId, String recordingType, String username) {
        long now = clock.now().toEpochMilli();
        long expiresAt = now + tokenExpiryDuration.toMillis();

        // Generate unique token ID
        String tokenId = UUID.randomUUID().toString();

        // Create JWT claims
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("recording-download")
                        .jwtID(tokenId)
                        .claim("recordingId", recordingId)
                        .claim("recordingType", recordingType)
                        .claim("username", username)
                        .issueTime(new Date(now))
                        .expirationTime(new Date(expiresAt))
                        .build();

        try {
            // Sign the JWT
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();

            logger.debugv(
                    "Generated download token {0} for recording {1} ({2}) for user {3}, expires at"
                            + " {4}",
                    tokenId, recordingId, recordingType, username, new Date(expiresAt));

            return new TokenInfo(token, expiresAt);
        } catch (JOSEException e) {
            logger.error("Failed to sign JWT token", e);
            throw new RuntimeException("Failed to generate download token", e);
        }
    }

    /**
     * Generate a download token for an archived recording using the encodedKey
     *
     * @param encodedKey the base64-encoded key identifying the archived recording
     * @param username the username of the user requesting the token
     * @return the generated token information
     */
    public TokenInfo generateTokenForArchivedRecording(String encodedKey, String username) {
        long now = clock.now().toEpochMilli();
        long expiresAt = now + tokenExpiryDuration.toMillis();

        // Generate unique token ID
        String tokenId = UUID.randomUUID().toString();

        // Create JWT claims - store the encodedKey directly
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject("recording-download")
                        .jwtID(tokenId)
                        .claim("encodedKey", encodedKey)
                        .claim("recordingType", "archived")
                        .claim("username", username)
                        .issueTime(new Date(now))
                        .expirationTime(new Date(expiresAt))
                        .build();

        try {
            // Sign the JWT
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();

            logger.debugv(
                    "Generated download token {0} for archived recording {1} for user {2}, expires"
                            + " at {3}",
                    tokenId, encodedKey, username, new Date(expiresAt));

            return new TokenInfo(token, expiresAt);
        } catch (JOSEException e) {
            logger.error("Failed to sign JWT token", e);
            throw new RuntimeException("Failed to generate download token", e);
        }
    }

    /**
     * Validate a download token and mark it as used
     *
     * @param tokenString the token string to validate
     * @param recordingId the ID of the recording being accessed
     * @param recordingType the type of recording being accessed
     * @throws ForbiddenException if the token is invalid, expired, already used, or doesn't match
     *     the recording
     */
    public void validateAndConsumeToken(String tokenString, Long recordingId, String recordingType)
            throws ForbiddenException {
        long now = clock.now().toEpochMilli();

        try {
            // Parse and verify JWT signature
            SignedJWT signedJWT = SignedJWT.parse(tokenString);
            if (!signedJWT.verify(verifier)) {
                logger.warnv("Invalid token signature");
                throw new ForbiddenException("Invalid token signature");
            }

            // Extract claims
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String tokenId = claims.getJWTID();
            Long tokenRecordingId = claims.getLongClaim("recordingId");
            String tokenRecordingType = claims.getStringClaim("recordingType");
            Date expirationTime = claims.getExpirationTime();

            // Check expiration
            if (expirationTime == null || now >= expirationTime.getTime()) {
                logger.warnv("Expired token: {0}", tokenId);
                throw new ForbiddenException("Token has expired");
            }

            // Check recording match
            if (!recordingId.equals(tokenRecordingId)
                    || !recordingType.equals(tokenRecordingType)) {
                logger.warnv(
                        "Token recording mismatch. Expected: {0}/{1}, Token: {2}/{3}",
                        recordingId, recordingType, tokenRecordingId, tokenRecordingType);
                throw new ForbiddenException("Token is not valid for this recording");
            }

            // Check if token has already been used (single-use enforcement)
            Long previousExpiry = usedTokens.putIfAbsent(tokenId, expirationTime.getTime());
            if (previousExpiry != null) {
                logger.warnv("Token already used: {0}", tokenId);
                throw new ForbiddenException("Token has already been used");
            }

            logger.debugv(
                    "Token validated and consumed: {0} for recording {1}/{2}",
                    tokenId, recordingId, recordingType);

        } catch (ParseException e) {
            logger.warnv("Failed to parse token: {0}", e.getMessage());
            throw new ForbiddenException("Invalid token format");
        } catch (JOSEException e) {
            logger.warnv("Token verification failed: {0}", e.getMessage());
            throw new ForbiddenException("Token verification failed");
        }
    }

    /**
     * Validate a download token for an archived recording and mark it as used
     *
     * @param tokenString the token string to validate
     * @param encodedKey the encodedKey of the recording being accessed
     * @throws ForbiddenException if the token is invalid, expired, already used, or doesn't match
     *     the recording
     */
    public void validateAndConsumeTokenForArchivedRecording(String tokenString, String encodedKey)
            throws ForbiddenException {
        long now = clock.now().toEpochMilli();

        logger.infov(
                "Starting token validation for encodedKey: {0}, token length: {1}",
                encodedKey, tokenString != null ? tokenString.length() : 0);

        try {
            // Parse and verify JWT signature
            SignedJWT signedJWT = SignedJWT.parse(tokenString);
            if (!signedJWT.verify(verifier)) {
                logger.warnv("Invalid token signature");
                throw new ForbiddenException("Invalid token signature");
            }

            // Extract claims
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String tokenId = claims.getJWTID();
            String tokenEncodedKey = claims.getStringClaim("encodedKey");
            String tokenRecordingType = claims.getStringClaim("recordingType");
            Date expirationTime = claims.getExpirationTime();

            logger.infov(
                    "Token claims - tokenId: {0}, tokenEncodedKey: {1}, tokenRecordingType: {2},"
                            + " expirationTime: {3}",
                    tokenId, tokenEncodedKey, tokenRecordingType, expirationTime);
            logger.infov(
                    "Comparing encodedKeys - Request: [{0}], Token: [{1}], Equal: {2}",
                    encodedKey, tokenEncodedKey, encodedKey.equals(tokenEncodedKey));

            // Check expiration
            if (expirationTime == null || now >= expirationTime.getTime()) {
                logger.warnv("Expired token: {0}", tokenId);
                throw new ForbiddenException("Token has expired");
            }

            // Check recording match
            if (!encodedKey.equals(tokenEncodedKey) || !"archived".equals(tokenRecordingType)) {
                logger.warnv(
                        "Token recording mismatch. Expected: {0}/archived, Token: {1}/{2}",
                        encodedKey, tokenEncodedKey, tokenRecordingType);
                throw new ForbiddenException("Token is not valid for this recording");
            }

            // Check if token has already been used (single-use enforcement)
            Long previousExpiry = usedTokens.putIfAbsent(tokenId, expirationTime.getTime());
            if (previousExpiry != null) {
                logger.warnv("Token already used: {0}", tokenId);
                throw new ForbiddenException("Token has already been used");
            }

            logger.infov(
                    "Token validated and consumed: {0} for archived recording {1}",
                    tokenId, encodedKey);

        } catch (ParseException e) {
            logger.errorv(e, "Failed to parse token: {0}", e.getMessage());
            throw new ForbiddenException("Invalid token format");
        } catch (JOSEException e) {
            logger.errorv(e, "Token verification failed: {0}", e.getMessage());
            throw new ForbiddenException("Token verification failed");
        }
    }

    /**
     * Clean up expired tokens from the in-memory cache. Runs periodically to prevent memory bloat.
     */
    @Scheduled(cron = "0 */5 * * * ?") // Every 5 minutes
    public void cleanupExpiredTokens() {
        long now = clock.now().toEpochMilli();
        int initialSize = usedTokens.size();

        // Remove expired tokens
        usedTokens.entrySet().removeIf(entry -> entry.getValue() < now);

        int removed = initialSize - usedTokens.size();
        if (removed > 0) {
            logger.debugv("Cleaned up {0} expired download tokens from cache", removed);
        }
    }

    /**
     * Get the current number of used tokens in the cache (for monitoring/debugging)
     *
     * @return the number of used tokens currently tracked
     */
    public int getUsedTokenCount() {
        return usedTokens.size();
    }

    /** Token information returned when generating a token */
    public record TokenInfo(String token, Long expiresAt) {}
}

// Made with Bob
