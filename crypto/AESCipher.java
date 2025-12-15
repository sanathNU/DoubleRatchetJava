package doubleratchet.crypto;

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

    // TODO: Implement AES-GCM encryption
    // Steps:
    // 1. Validate key is KEY_SIZE bytes
    // 2. Generate random nonce (NONCE_SIZE bytes)
    // 3. Create Cipher instance for ALGORITHM
    // 4. Create GCMParameterSpec with TAG_SIZE and nonce
    // 5. Create SecretKeySpec from key
    // 6. Init cipher in ENCRYPT_MODE
    // 7. If associatedData != null, call updateAAD()
    // 8. doFinal to get ciphertext (includes tag at end)
    // 9. Prepend nonce to output

    if (key == null || plaintext == null || associatedData == null) return null;
    if (key.length != KEY_SIZE || plaintext.length != NONCE_SIZE || associatedData.length != TAG_SIZE) return null;


    throw new UnsupportedOperationException("Implement me!");
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

    // TODO: Implement AES-GCM decryption
    // Steps:
    // 1. Validate key size and minimum ciphertext length
    // 2. Extract nonce (first NONCE_SIZE bytes)
    // 3. Extract ciphertext+tag (remaining bytes)
    // 4. Create Cipher, GCMParameterSpec, SecretKeySpec
    // 5. Init cipher in DECRYPT_MODE
    // 6. If associatedData != null, call updateAAD()
    // 7. doFinal - will throw if authentication fails!

    throw new UnsupportedOperationException("Implement me!");
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