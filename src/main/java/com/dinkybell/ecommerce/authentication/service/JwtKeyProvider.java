package com.dinkybell.ecommerce.authentication.service;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;

/**
 * JwtKeyProvider manages RSA key pair generation and persistence for JWT signing.
 * 
 * This component is responsible for:
 * - Generating or loading 2048-bit RSA key pairs for JWT token signing and verification
 * - Persisting keys in a JCEKS (Java Cryptography Extension KeyStore) format on disk
 * - Providing fallback in-memory key generation if keystore operations fail
 * - Ensuring keys are available at application startup via {@code @PostConstruct}
 * 
 * Key Management Strategy:
 * - On first startup: generates and saves a new RSA key pair to the configured keystore file
 * - On subsequent startups: loads the existing key pair from the keystore
 * - If keystore loading fails: falls back to generating a temporary in-memory key pair
 * 
 * The keystore is encrypted with a password and stored as a JCEKS file, which is
 * Java's native encrypted key storage format. This provides basic key protection
 * at rest. For production environments, consider using dedicated key management
 * solutions (e.g., AWS KMS, HashiCorp Vault).
 * 
 * Configuration Properties:
 * - {@code jwt.keystore.path}: File path where the keystore is stored
 * - {@code jwt.keystore.password}: Password protecting the keystore
 * - {@code jwt.keystore.alias}: Alias prefix for keys stored in the keystore
 */
@Component
@Slf4j
public class JwtKeyProvider {

    /** File path to the JCEKS keystore containing the RSA keys. */
    @Value("${jwt.keystore.path}") private String keystorePath;
    
    /** Password used to encrypt and decrypt the keystore. */
    @Value("${jwt.keystore.password}") private String keystorePassword;
    
    /** Alias prefix for keys stored in the keystore (suffixed with "_private" and "_public"). */
    @Value("${jwt.keystore.alias}") private String keyAlias;
    
    /** The RSA key pair used for signing and verifying JWT tokens. */
    @Getter
    private KeyPair keyPair;

    /**
     * Initializes the JWT key provider at application startup.
     * 
     * This method is called automatically after the bean is created (via {@code @PostConstruct}).
     * It performs the following sequence:
     * 1. Checks if a keystore file already exists at the configured path
     * 2. If exists: loads the key pair from the keystore
     * 3. If not exists: generates a new key pair and saves it to a new keystore
     * 4. On failure: generates a temporary in-memory key pair as fallback
     * 
     * The fallback behavior ensures the application can start even if keystore
     * operations fail, though keys will be lost on application restart.
     */
    @PostConstruct
    public void init() {

        try {
            Path path = Paths.get(keystorePath);
            if (Files.exists(path)) {
                log.info("Loading JWT keystore from {}", keystorePath);
                keyPair = loadKeyPairFromKeystore();
            } else {
                log.info("Creating new JWT keystore at {}", keystorePath);
                keyPair = generateAndSaveKeyPair();
            }
        } catch(Exception e) {
            log.warn("Fallback in-memory RSA key generation: {}", e.getMessage());
            keyPair = generateInMemoryKeyPair();
        }
    }

    /**
     * Returns the private key from the key pair.
     * 
     * This private key is used for signing JWT tokens. It should never be
     * shared or exposed to clients.
     * 
     * @return the RSA private key
     */
    public PrivateKey getPrivateKey() { return keyPair.getPrivate(); }
    
    /**
     * Returns the public key from the key pair.
     * 
     * This public key is used by clients to verify JWT token signatures.
     * It can be safely shared with clients via a public endpoint.
     * 
     * @return the RSA public key
     */
    public PublicKey getPublicKey() { return keyPair.getPublic(); }

    /**
     * Generates a new 2048-bit RSA key pair in memory.
     * 
     * This method creates a temporary key pair without persisting it. Used for
     * initial key generation or as a fallback when keystore operations fail.
     * 
     * @return a new RSA KeyPair with 2048-bit key size
     * @throws RuntimeException if RSA algorithm is not available (should not occur on modern JVMs)
     */
    private KeyPair generateInMemoryKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Cannot generate RSA keys in-memory", e);
        }
    }

    /**
     * Generates a new RSA key pair and persists it to the keystore file.
     * 
     * This method combines key generation and persistence:
     * 1. Generates a new in-memory key pair
     * 2. Saves the key pair to the JCEKS keystore file
     * 3. Returns the generated key pair for immediate use
     * 
     * @return the generated and saved RSA key pair
     * @throws Exception if key generation or persistence fails
     */
    private KeyPair generateAndSaveKeyPair() throws Exception {
        KeyPair kp = generateInMemoryKeyPair();
        saveKeyPairSimple(kp);
        return kp;
    }

    /**
     * Saves an RSA key pair to a JCEKS keystore file.
     * 
     * This method:
     * 1. Creates the directory structure if it doesn't exist
     * 2. Creates a new JCEKS keystore instance
     * 3. Converts the RSA keys to SecretKeySpec format for storage
     * 4. Stores both private and public keys with suffixed aliases
     * 5. Persists the keystore to disk with password protection
     * 
     * Note: JCEKS stores RSA keys as SecretKeySpec which is not ideal for true
     * PKI scenarios, but sufficient for JWT signing in this use case.
     * 
     * @param kp the RSA key pair to save
     * @throws Exception if keystore creation or file I/O operations fail
     */
    private void saveKeyPairSimple(KeyPair kp) throws Exception {
        Path path = Paths.get(keystorePath);
        if (path.getParent() != null) Files.createDirectories(path.getParent());

        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(null, null);

        SecretKeySpec priv = new SecretKeySpec(kp.getPrivate().getEncoded(), "RSA");
        SecretKeySpec pub = new SecretKeySpec(kp.getPublic().getEncoded(), "RSA");

        ks.setKeyEntry(keyAlias + "_private", priv, keystorePassword.toCharArray(), null);
        ks.setKeyEntry(keyAlias + "_public", pub, keystorePassword.toCharArray(), null);

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            ks.store(fos, keystorePassword.toCharArray());
        }

        log.info("JCEKS keystore created at {}", keystorePath);
    }

    /**
     * Loads an RSA key pair from an existing JCEKS keystore file.
     * 
     * This method:
     * 1. Creates a JCEKS keystore instance
     * 2. Loads the keystore from the file using the configured password
     * 3. Retrieves the private and public keys by their suffixed aliases
     * 4. Reconstructs the RSA keys using KeyFactory from their encoded formats
     * 5. Returns a KeyPair containing both keys
     * 
     * The keys are decoded from PKCS8 (private) and X.509 (public) formats,
     * which are standard Java key encoding formats.
     * 
     * @return the loaded RSA key pair from the keystore
     * @throws Exception if keystore loading or key reconstruction fails
     */
    private KeyPair loadKeyPairFromKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }

        SecretKeySpec privSpec = (SecretKeySpec) ks.getKey(keyAlias + "_private", keystorePassword.toCharArray());
        SecretKeySpec pubSpec = (SecretKeySpec) ks.getKey(keyAlias + "_public", keystorePassword.toCharArray());

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey priv = kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(privSpec.getEncoded()));
        PublicKey pub = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(pubSpec.getEncoded()));

        return new KeyPair(pub, priv);
    }
}

