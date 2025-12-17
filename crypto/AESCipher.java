package doubleratchet.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AES-256-GCM Authenticated Encryption.
 *
 * GCM (Galois/Counter Mode) provides:
 * - Confidentiality (encryption)
 * - Authenticity (built-in MAC)
 * - Associated Data support (authenticate unencrypted header)
 *
 * TODO: Implement AES-256-GCM encryption and decryption
 */
public class AESCipher {

  private static final String ALGORITHM = "AES/GCM/NoPadding";
  private static final int KEY_SIZE = 32;      // 256 bits
  private static final int NONCE_SIZE = 12;    // 96 bits (GCM recommended)
  private static final int TAG_SIZE = 128;     // 128-bit auth tag

  /**
   * Encrypt plaintext using AES-256-GCM.
   *
   * Output format: nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
   *
   * @param key 256-bit encryption key
   * @param plaintext data to encrypt
   * @param associatedData additional authenticated data (can be null)
   * @return nonce + ciphertext + tag
   * @throws GeneralSecurityException on crypto errors
   */
  public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] associatedData)
      throws GeneralSecurityException {

    // Steps:
    // 1. Validate key is KEY_SIZE bytes
    if (key == null || plaintext == null) {
      throw new IllegalArgumentException("Key and plaintext must not be null");
    }

    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("Key must be 256 bits");
    }

    // 2. Generate random nonce (NONCE_SIZE bytes)
    byte[] nonce = new byte[NONCE_SIZE];
    SecureRandom random = new SecureRandom();
    random.nextBytes(nonce);

    // 3. Create Cipher instance for ALGORITHM
    Cipher cipher = Cipher.getInstance(ALGORITHM);

    // 4. Create GCMParameterSpec with TAG_SIZE and nonce
    GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, nonce);


    // 5. Create SecretKeySpec from key
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

    // 6. Init cipher in ENCRYPT_MODE
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

    // 7. If associatedData != null, call updateAAD()
    if (associatedData != null) {
      cipher.updateAAD(associatedData);
    }

    // 8. Encrypt (ciphertext + tag)
    byte[] ciphertextAndTag = cipher.doFinal(plaintext);

    // 9. Prepend nonce to output
    byte[] output = new byte[nonce.length + ciphertextAndTag.length];
    System.arraycopy(nonce, 0, output, 0, nonce.length);
    System.arraycopy(ciphertextAndTag, 0, output, nonce.length, ciphertextAndTag.length);

    return output;
  }

  /**
   * Decrypt ciphertext using AES-256-GCM.
   *
   * Input format: nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
   *
   * @param key 256-bit decryption key
   * @param ciphertextWithNonce nonce + ciphertext + tag
   * @param associatedData additional authenticated data (must match encrypt)
   * @return decrypted plaintext
   * @throws GeneralSecurityException on crypto errors or auth failure
   */
  public static byte[] decrypt(byte[] key, byte[] ciphertextWithNonce, byte[] associatedData)
      throws GeneralSecurityException {

    // Steps:
    // 1. Validate key size and minimum ciphertext length
    if (key == null || ciphertextWithNonce == null) {
      throw new IllegalArgumentException("Key and ciphertext must not be null");
    }
    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("Key must be 256 bits");
    }

    if (ciphertextWithNonce.length < NONCE_SIZE + 16) {
      throw new IllegalArgumentException("Ciphertext too short");
    }

    // 2. Extract nonce (first NONCE_SIZE bytes)
    byte[] nonce = Arrays.copyOfRange(
        ciphertextWithNonce, 0, NONCE_SIZE);

    // 3. Extract ciphertext+tag (remaining bytes)
    byte[] ciphertextAndTag = Arrays.copyOfRange(
        ciphertextWithNonce, NONCE_SIZE, ciphertextWithNonce.length);

    // 4. Create Cipher, GCMParameterSpec, SecretKeySpec
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, nonce);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

    // 5. Init cipher in DECRYPT_MODE
    cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

    // 6. If associatedData != null, call updateAAD()
    if (associatedData != null) {
      cipher.updateAAD(associatedData);
    }

    // 7. doFinal - will throw if authentication fails!
    return cipher.doFinal(ciphertextAndTag);

  }

  /**
   * Encrypt with header as associated data.
   * This is the typical Double Ratchet usage: authenticate the header
   * but only encrypt the message body.
   *
   * @param key message key
   * @param plaintext message body
   * @param header serialized message header
   * @return encrypted message
   */
  public static byte[] encryptWithHeader(byte[] key, byte[] plaintext, byte[] header)
      throws GeneralSecurityException {
    return encrypt(key, plaintext, header);
  }

  /**
   * Decrypt with header as associated data.
   *
   * @param key message key
   * @param ciphertext encrypted message
   * @param header serialized message header (must match)
   * @return decrypted message body
   */
  public static byte[] decryptWithHeader(byte[] key, byte[] ciphertext, byte[] header)
      throws GeneralSecurityException {
    return decrypt(key, ciphertext, header);
  }
}