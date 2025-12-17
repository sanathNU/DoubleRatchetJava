package doubleratchet.ratchet;

import doubleratchet.crypto.HKDF;

/**
 * Symmetric-key ratchet (KDF chain) operations.
 *
 * The symmetric ratchet generates message keys from chain keys.
 * Each step produces:
 * - A new chain key (for the next message)
 * - A message key (for encrypting/decrypting this message)
 *
 * Chain key derivation is one-way: you cannot derive previous
 * keys from current keys (forward secrecy within a chain).
 *
 */
public class SymmetricRatchet {

  private static final int MAX_SKIP = 1000;

  /**
   * Result of a symmetric ratchet step.
   */
  public record RatchetStepResult(byte[] newChainKey, byte[] messageKey) {}

  /**
   * Perform one step of the symmetric ratchet.
   *
   * Given a chain key, derive:
   * 1. The next chain key
   * 2. A message key for encryption/decryption
   *
   * The Signal spec uses:
   * - Message Key = HMAC(chain_key, 0x01)
   * - New Chain Key = HMAC(chain_key, 0x02)
   *
   * Alternatively, you can use HKDF:
   * - output = HKDF(salt=chain_key, ikm=chain_key, info="MessageKey", len=64)
   * - Split into message_key and new_chain_key
   *
   * @param chainKey current chain key (32 bytes)
   * @return new chain key and message key
   */
  public static RatchetStepResult step(byte[] chainKey) {
    if (chainKey == null || chainKey.length != 32) {
      throw new IllegalArgumentException("Chain key must be 32 bytes");
    }
    byte[][] derived = HKDF.kdfChainKey(chainKey);
    return new RatchetStepResult(derived[0], derived[1]);
  }

  /**
   * Skip ahead in the chain, storing all skipped message keys.
   *
   * Used when receiving a message with a higher message number
   * than expected (out-of-order delivery).
   *
   * @param state the ratchet state to update
   * @param untilMessageNumber skip until this message number
   * @throws IllegalStateException if too many messages would be skipped
   */
  public static void skipMessageKeys(RatchetState state, int untilMessageNumber) {

    // 2. While receivingMessageNumber < untilMessageNumber:
    //    a. Step the receiving chain
    //    b. Store the message key in skippedMessageKeys
    //    c. Update receivingChainKey
    //    d. Increment receivingMessageNumber

    int currentMsgNum = state.getReceivingMessageNumber();
    int toSkip = untilMessageNumber - currentMsgNum;

    // 1. Check that we won't exceed MAX_SKIP
    if (toSkip > MAX_SKIP) {
      throw new IllegalStateException(
          "Too many skipped messages: " + toSkip + " exceeds max " + MAX_SKIP);
    }

    if (toSkip < 0) {
      throw new IllegalStateException();
    }

    byte[] receivingChainKey = state.getReceivingChainKey();
    if (receivingChainKey == null) {
      return;
    }

    while (state.getReceivingMessageNumber() < untilMessageNumber) {
      RatchetStepResult result = step(receivingChainKey);

      // Store the message key for later retrieval
      state.storeSkippedMessageKey(
          state.getRemoteDHPublicKey(),
          state.getReceivingMessageNumber(),
          result.messageKey()
      );

      // Update for next iteration
      receivingChainKey = result.newChainKey();
      state.incrementReceivingMessageNumber();
    }

    // Update state with final chain key
    state.setReceivingChainKey(receivingChainKey);
  }

  /**
   * Advance the sending chain and get a message key.
   *
   * @param state the ratchet state
   * @return message key for encryption
   */
  public static byte[] advanceSendingChain(RatchetState state) {
    // 1. Call step(sendingChainKey)
    RatchetStepResult result = step(state.getSendingChainKey());

    // 2. Update state with new chain key
    state.setSendingChainKey(result.newChainKey());
    // 3. Increment sending message number
    state.incrementSendingMessageNumber();
    // 4. Return message key

    return result.messageKey();

  }

  /**
   * Advance the receiving chain and get a message key.
   *
   * @param state the ratchet state
   * @return message key for decryption
   */
  public static byte[] advanceReceivingChain(RatchetState state) {
    // Same pattern as advanceSendingChain but for receiving
    RatchetStepResult result = step(state.getReceivingChainKey());

    state.setReceivingChainKey(result.newChainKey());
    state.incrementReceivingMessageNumber();

    return result.messageKey();
  }
}