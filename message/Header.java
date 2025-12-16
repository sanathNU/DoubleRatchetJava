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
  public static final int DH_PUBLIC_KEY_SIZE = 32;
  public static final int HEADER_SIZE = 32 + 4 + 4;

  private final byte[] dhPublicKey;
  private final int previousChainLength;
  private final int messageNumber;
  private final int chainCounter;

  public Header(byte[] dhPublicKey, int previousChainLength, int messageNumber, int chainCounter) {
    this.dhPublicKey = Arrays.copyOf(dhPublicKey, dhPublicKey.length);
    this.previousChainLength = previousChainLength;
    this.messageNumber = messageNumber;
    this.chainCounter = chainCounter;
  }

  /**
   * Serialize header to bytes for transmission.
   *
   * @return serialized header
   */
  public byte[] toBytes() {
    // dhPublicKey length + 4 bytes per int
    ByteBuffer buffer = ByteBuffer.allocate(
        dhPublicKey.length + Integer.BYTES * 2
    );

    buffer.put(dhPublicKey);
    buffer.putInt(previousChainLength);
    buffer.putInt(messageNumber);
    buffer.putInt(chainCounter);

    return buffer.array();
  }

  /**
   * Deserialize header from bytes.
   *
   * @param data serialized header
   * @return Header object
   */
  public static Header fromBytes(byte[] data) {
    if (data == null) {
      throw new IllegalArgumentException("Data cannot be null");
    }

    if (data.length != HEADER_SIZE) {
      throw new IllegalArgumentException(
          "Invalid header length: " + data.length
      );
    }

    ByteBuffer buffer = ByteBuffer.wrap(data);

    byte[] dhPublicKey = new byte[DH_PUBLIC_KEY_SIZE];
    buffer.get(dhPublicKey);

    int previousChainLength = buffer.getInt();
    int messageNumber = buffer.getInt();
    int chainCounter = buffer.getInt();

    return new Header(dhPublicKey, previousChainLength, messageNumber, chainCounter);
  }

  // Getters
  public byte[] getDhPublicKey() { return Arrays.copyOf(dhPublicKey, dhPublicKey.length); }
  public int getPreviousChainLength() { return previousChainLength; }
  public int getMessageNumber() { return messageNumber; }
  public int getChainCounter() { return chainCounter; }
}