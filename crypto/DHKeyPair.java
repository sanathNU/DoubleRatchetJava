package doubleratchet.crypto;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import java.util.Arrays;

/**
 * X25519 Diffie-Hellman key pair for the DH ratchet.
 *
 * X25519 is an elliptic curve Diffie-Hellman function using Curve25519.
 * It provides ~128 bits of security with 32-byte keys.
 *
 * Java 11+ provides X25519 via the XDH algorithm.
 *
 */
public class DHKeyPair {

  private static final String ALGORITHM = "X25519";
  private static final String KEY_AGREEMENT = "XDH";

  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final byte[] publicKeyBytes; // Raw 32-byte public key

  /**
   * Create a DHKeyPair from existing keys.
   */
  private DHKeyPair(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicKeyBytes = extractPublicKeyBytes(publicKey);
  }

  /**
   * Generate a new random X25519 key pair.
   *
   * @return new DHKeyPair
   */
  public static DHKeyPair generate() {
    // Steps:
    // 1. Get KeyPairGenerator for ALGORITHM ("X25519")
    // 2. Generate key pair
    // 3. Return new DHKeyPair(privateKey, publicKey)

    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
      KeyPair kp = kpg.generateKeyPair();
      return new DHKeyPair(kp.getPrivate(), kp.getPublic());
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("X25519 keypair generation failed!",e);
    }
  }

  /**
   * Reconstruct a public key from raw bytes.
   * Used when receiving a public key from the other party.
   *
   * @param publicKeyBytes 32-byte X25519 public key
   * @return PublicKey object
   */
  public static PublicKey publicKeyFromBytes(byte[] publicKeyBytes) {

    if (publicKeyBytes.length != 32)
      throw new IllegalArgumentException("X25519 public key must be 32 bytes");

    try {
      // Convert little-endian -> big-endian
      byte[] reversed = reverse(publicKeyBytes);
      // 1. Create NamedParameterSpec for "X25519"
      NamedParameterSpec paramSpec = new NamedParameterSpec(ALGORITHM);
      // 2. Create XECPublicKeySpec with the spec and BigInteger from bytes
      XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, new BigInteger(1, reversed));
      // 3. Get KeyFactory for "XDH"
      KeyFactory kf = KeyFactory.getInstance(KEY_AGREEMENT);
      // 4. Generate public key from spec
      return kf.generatePublic(pubSpec);

    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to reconstruct X25519 public key", e);
    }
  }

  /**
   * Extract raw bytes from a PublicKey.
   *
   * @param publicKey X25519 public key
   * @return 32-byte raw public key
   */
  private static byte[] extractPublicKeyBytes(PublicKey publicKey) {
    try {
      XECPublicKey xecPub = (XECPublicKey) publicKey;
      BigInteger u = xecPub.getU();

      byte[] be = u.toByteArray();       // big-endian
      byte[] le = new byte[32];          // always 32 bytes

      // Copy big-endian → little-endian padded
      int copy = Math.min(be.length, 32);
      for (int i = 0; i < copy; i++) {
        le[i] = be[be.length - 1 - i];
      }
      return le;

    } catch (ClassCastException e) {
      throw new IllegalArgumentException("Not an X25519 public key", e);
    }
  }

  /**
   * Perform Diffie-Hellman key agreement.
   *
   * @param theirPublicKey the other party's public key
   * @return 32-byte shared secret
   */
  public byte[] dh(PublicKey theirPublicKey) {
    // Steps:
    try {
      // 1. Get KeyAgreement for "XDH"
      KeyAgreement ka = KeyAgreement.getInstance(KEY_AGREEMENT);
      // 2. Init with this.privateKey
      ka.init(privateKey);
      // 3. doPhase with theirPublicKey
      ka.doPhase(theirPublicKey, true);
      // 4. generateSecret()
      return ka.generateSecret();  // 32 bytes

    } catch (GeneralSecurityException e) {
      throw new RuntimeException("X25519 DH failed", e);
    }
  }

  /**
   * Convenience method: DH from raw public key bytes.
   *
   * @param theirPublicKeyBytes 32-byte public key
   * @return 32-byte shared secret
   */
  public byte[] dh(byte[] theirPublicKeyBytes) {
    PublicKey theirKey = publicKeyFromBytes(theirPublicKeyBytes);
    return dh(theirKey);
  }

  // Getters

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Get the raw 32-byte public key for transmission.
   */
  public byte[] getPublicKeyBytes() {
    return Arrays.copyOf(publicKeyBytes, publicKeyBytes.length);
  }

  private static byte[] reverse(byte[] arr) {
    byte[] reversed = new byte[arr.length];
    for (int i = 0; i < arr.length; i++) {
      reversed[i] = arr[arr.length - 1 - i];
    }
    return reversed;
  }
}