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
    if (header == null || ciphertext == null) {
      throw new IllegalArgumentException("Header and ciphertext cannot be null");
    }
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
    byte[] headerBytes = header.toBytes();
    int totalLength =
        Integer.BYTES + headerBytes.length + ciphertext.length;

    ByteBuffer buffer = ByteBuffer.allocate(totalLength);

    buffer.putInt(headerBytes.length);
    buffer.put(headerBytes);
    buffer.put(ciphertext);

    return buffer.array();
  }

  /**
   * Deserialize message from bytes.
   *
   * @param data serialized message
   * @return Message object
   */
  public static Message fromBytes(byte[] data) {
    if (data == null || data.length < Integer.BYTES) {
      throw new IllegalArgumentException("Invalid message data");
    }

    ByteBuffer buffer = ByteBuffer.wrap(data);

    int headerLength = buffer.getInt();
    if (headerLength <= 0 || headerLength > buffer.remaining()) {
      throw new IllegalArgumentException("Invalid header length");
    }

    byte[] headerBytes = new byte[headerLength];
    buffer.get(headerBytes);

    byte[] ciphertext = new byte[buffer.remaining()];
    buffer.get(ciphertext);

    Header header = Header.fromBytes(headerBytes);
    return new Message(header, ciphertext);
  }

  // Getters
  public Header getHeader() { return header; }
  public byte[] getCiphertext() { return Arrays.copyOf(ciphertext, ciphertext.length); }
}