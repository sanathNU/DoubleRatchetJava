package doubleratchet.crypto;

import static java.lang.Math.ceil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


/**
 * HKDF (HMAC-based Key Derivation Function) as per RFC 5869.
 *
 * HKDF consists of two stages:
 * 1. Extract: Concentrate entropy from input key material
 * 2. Expand: Generate output key material of desired length
 *
 */
public class HKDF {
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final int HASH_LEN = 32;

  /**
   * Compute HMAC-SHA256.
   *
   * @param key HMAC key
   * @param data data to authenticate
   * @return HMAC result (32 bytes)
   */
  private static byte[] hmacSha256(byte[] key, byte[] data) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGORITHM);
      mac.init(keySpec);
      return mac.doFinal(data);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new RuntimeException("Failed to compute HMAC-SHA256", e);
    }
  }

  /**
   * HKDF-Extract: Derive a pseudorandom key from input key material.
   *
   * PRK = HMAC-Hash(salt, IKM)
   *
   * @param salt optional salt (can be null or empty, defaults to zeros)
   * @param inputKeyMaterial input key material
   * @return pseudorandom key (32 bytes)
   */
  public static byte[] extract(byte[] salt, byte[] inputKeyMaterial) {

    if (salt == null || salt.length == 0) {
      salt = new byte[HASH_LEN];
    }
    return hmacSha256(salt, inputKeyMaterial);
  }

  /**
   * HKDF-Expand: Expand pseudorandom key to desired length.
   *
   * T(0) = empty
   * T(i) = HMAC-Hash(PRK, T(i-1) | info | i)  where i is a single byte
   * OKM = first L bytes of T(1) | T(2) | ...
   *
   * @param prk pseudorandom key (from extract)
   * @param info context/application-specific info (can be null)
   * @param length desired output length in bytes
   * @return output key material
   */
  public static byte[] expand(byte[] prk, byte[] info, int length) {
    // Steps:
    // 1. Calculate how many HMAC iterations needed: ceil(length / HASH_LENGTH)
    // 2. Validate length <= 255 * HASH_LENGTH
    // 3. Loop: T(i) = HMAC(PRK, T(i-1) || info || byte(i))
    // 4. Concatenate and truncate to exact length
    if (length < 0) {
      throw new IllegalArgumentException("Length must be non-negative");
    }
    if (length > 255 * HASH_LEN) {
      throw new IllegalArgumentException("Length must be less than 255 * HASH_LEN");
    }
    int steps = (int) Math.ceil((double) length / HASH_LEN);

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] previousT = new byte[0];
    for (int i = 1; i <= steps; i++) {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      try {
        // T(i) = HMAC(PRK, T(i-1) || info || byte(i))
        buffer.write(previousT);
        buffer.write(info);
        buffer.write((byte) i);
      } catch (IOException e) {
        throw new RuntimeException(e); // ByteArrayOutputStream should never throw
      }
      previousT = hmacSha256(prk, buffer.toByteArray());
      output.write(previousT, 0, previousT.length);
    }


    byte[] okm = output.toByteArray();
    return Arrays.copyOf(okm, length);
  }
  /**
   * Convenience method: Extract-then-Expand in one call.
   *
   * @param salt salt for extract
   * @param inputKeyMaterial input key material
   * @param info context info for expand
   * @param length desired output length
   * @return derived key material
   */
  public static byte[] deriveKey(byte[] salt, byte[] inputKeyMaterial,
                                 byte[] info, int length) {
    byte[] prk = extract(salt, inputKeyMaterial);
    return expand(prk, info, length);
  }

  /**
   * Double Ratchet KDF for root chain.
   * Derives both new root key and chain key from DH output.
   *
   * @param rootKey current root key (used as salt)
   * @param dhOutput DH shared secret
   * @return array of [newRootKey, chainKey] (32 bytes each)
   */
  public static byte[][] kdfRootKey(byte[] rootKey, byte[] dhOutput) {
    // Step 1: HKDF-Extract — PRK = HMAC(rootKey, dhOutput)
    byte[] prk = extract(rootKey, dhOutput);

    // Step 2: HKDF-Expand — derive 64 bytes
    byte[] okm = expand(prk, "DoubleRatchetRootKey".getBytes(StandardCharsets.UTF_8), 64);

    // Step 3: Split into two 32-byte keys
    byte[] newRootKey = Arrays.copyOfRange(okm, 0, 32);
    byte[] chainKey   = Arrays.copyOfRange(okm, 32, 64);

    return new byte[][] { newRootKey, chainKey };

  }

  /**
   * Double Ratchet KDF for chain key.
   * Derives new chain key and message key.
   *
   * @param chainKey current chain key
   * @return array of [newChainKey, messageKey] (32 bytes each)
   */
  public static byte[][] kdfChainKey(byte[] chainKey) {
    // Option 2: Use HKDF with chainKey as both salt and IKM
   byte[] prk = extract(chainKey, chainKey);
   byte[] okm = expand(prk,  "DoubleRatchetChainKey".getBytes(StandardCharsets.UTF_8), 64);

    byte[] newChainKey = Arrays.copyOfRange(okm, 0, 32);
    byte[] messageKey  = Arrays.copyOfRange(okm, 32, 64);

    return new byte[][] { newChainKey, messageKey };
  }
}