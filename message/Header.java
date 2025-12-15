package doubleratchet.header;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Message header containing DH public key and counters.
 *
 * Header format (44 bytes total):
 * - DH public key: 32 bytes
 * - Previous chain length: 4 bytes (int)
 * - Message number: 4 bytes (int)
 * - Counter for this chain: 4 bytes (int)
 *
 * The header is authenticated but not encrypted
 */
public class Header {
  public static final int HEADER_SIZE = 32 + 4 + 4;

  private final byte[] dhPublicKey;
  private final int previousChainLength;
  private final int messageNumber;

  public Header(byte[] dhPublicKey, int previousChainLength, int messageNumber) {
    this.dhPublicKey = Arrays.copyOf(dhPublicKey, dhPublicKey.length);
    this.previousChainLength = previousChainLength;
    this.messageNumber = messageNumber;
  }

  /**
   * Serialize header to bytes for transmission.
   *
   * @return serialized header
   */
  public byte[] toBytes() {
    // TODO: Serialize to bytes
    // Use ByteBuffer for easy int conversion
    // Format: dhPublicKey || previousChainLength || messageNumber

  }

  /**
   * Deserialize header from bytes.
   *
   * @param data serialized header
   * @return Header object
   */
  public static Header fromBytes(byte[] data) {
    // TODO: Deserialize from bytes
    // Validate length, extract fields using ByteBuffer

    throw new UnsupportedOperationException("Implement me!");
  }

  // Getters
  public byte[] getDhPublicKey() { return Arrays.copyOf(dhPublicKey, dhPublicKey.length); }
  public int getPreviousChainLength() { return previousChainLength; }
  public int getMessageNumber() { return messageNumber; }
}