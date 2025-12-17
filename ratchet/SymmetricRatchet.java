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
 * TODO: Implement the symmetric ratchet step
 */
public class SymmetricRatchet {

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
    // TODO: Implement symmetric ratchet step
    // Use HKDF.kdfChainKey or implement directly with HMAC

    throw new UnsupportedOperationException("Implement me!");
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
    // TODO: Implement message key skipping
    // Steps:
    // 1. Check that we won't exceed MAX_SKIP
    // 2. While receivingMessageNumber < untilMessageNumber:
    //    a. Step the receiving chain
    //    b. Store the message key in skippedMessageKeys
    //    c. Update receivingChainKey
    //    d. Increment receivingMessageNumber

    throw new UnsupportedOperationException("Implement me!");
  }

  /**
   * Advance the sending chain and get a message key.
   *
   * @param state the ratchet state
   * @return message key for encryption
   */
  public static byte[] advanceSendingChain(RatchetState state) {
    // TODO: Step the sending chain
    // 1. Call step(sendingChainKey)
    // 2. Update state with new chain key
    // 3. Increment sending message number
    // 4. Return message key

    throw new UnsupportedOperationException("Implement me!");
  }

  /**
   * Advance the receiving chain and get a message key.
   *
   * @param state the ratchet state
   * @return message key for decryption
   */
  public static byte[] advanceReceivingChain(RatchetState state) {
    // TODO: Step the receiving chain
    // Same pattern as advanceSendingChain but for receiving

    throw new UnsupportedOperationException("Implement me!");
  }
}