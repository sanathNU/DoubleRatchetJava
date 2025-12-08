package doubleratchet.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Utility functions for cryptographic operations.
 */
public class CryptoUtils {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * Generate cryptographically secure random bytes.
   *
   * @param length number of bytes to generate
   * @return random byte array
   */
  public static byte[] randomBytes(int length) {
    byte[] bytes = new byte[length];
    SECURE_RANDOM.nextBytes(bytes);
    return bytes;
  }


  /**
   * Constant-time byte array comparison to prevent timing attacks.
   *
   * @param a a first byte array
   * @param b b second byte array
   * @return true if arrays are equal
   */
  public static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a == null || b == null) return false;
    if (a.length != b.length) return false;

    int result = 0;
    for (int i = 0; i< a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /**
   * Concatenate multiple byte arrays.
   *
   * @param arrays array bytes to concatenate
   * @return concatenated result
   */
  public static byte[] concat(byte[]... arrays) {
    int totalLength = Arrays.stream(arrays)
        .filter(Objects::nonNull)
        .mapToInt(a ->a.length)
        .sum();
    byte[] result = new byte[totalLength];
    int pos = 0;
    for (byte[] arr: arrays) {
      System.arraycopy(arr, 0, result, pos, arr.length);
      pos += arr.length;
    }
    return result;
  }

  /**
   * Convert byte array to hex string for debugging.
   *
   * @param bytes input bytes
   * @return hex string representation of bytes
   */
  public static String bytesToHex(byte[] bytes) {
    StringBuilder result = new StringBuilder();
    for (byte b: bytes) {
      result.append(String.format("%02x", b));
    }
    return result.toString();
  }

  /**
   * Securely zero out a byte array (for key material cleanup).
   *
   * @param data data array to zero.
   */
  public static void zeroize(byte[] data) {
    Arrays.fill(data, (byte) 0);
  }
}