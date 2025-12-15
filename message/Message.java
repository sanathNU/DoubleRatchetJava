package doubleratchet.message;

import java.nio.ByteBuffer;
import java.util.Arrays;
import doubleratchet.header.Header;

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

/**
 * Complete encrypted message with header and ciphertext.
 */
class Message {
  private final Header header;
  private final byte[] ciphertext;

  public Message(Header header, byte[] ciphertext) {
    this.header = header;
    this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
  }
  /**
   * Serialize complete message for transmission.
   *
   * Format:
   * - Header length: 4 bytes
   * - Header: variable
   * - Ciphertext: remaining bytes
   *
   * @return serialized message
   */
  public byte[] toBytes() {
    // TODO: Serialize message
    // Include header length for easy parsing

    throw new UnsupportedOperationException("Implement me!");
  }

  /**
   * Deserialize message from bytes.
   *
   * @param data serialized message
   * @return Message object
   */
  public static Message fromBytes(byte[] data) {
    // TODO: Deserialize message

    throw new UnsupportedOperationException("Implement me!");
  }

  // Getters
  public Header getHeader() { return header; }
  public byte[] getCiphertext() { return Arrays.copyOf(ciphertext, ciphertext.length); }
}