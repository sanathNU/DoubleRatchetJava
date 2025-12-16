package doubleratchet.ratchet;

import doubleratchet.crypto.DHKeyPair;
import doubleratchet.crypto.HKDF;

/**
 * Diffie-Hellman ratchet operations.
 *
 * The DH ratchet provides:
 * - Forward secrecy: compromise of current keys doesn't reveal past messages
 * - Break-in recovery: if keys are compromised, future messages become
 *   secure again after a few exchanges
 *
 * When receiving a new DH public key from the peer:
 * 1. Perform DH with our current private key
 * 2. Derive new receiving chain key
 * 3. Generate new DH key pair
 * 4. Perform DH with new private key
 * 5. Derive new sending chain key
 *
 */
public class DHRatchet {

  /**
   * Perform a DH ratchet step when receiving a new public key.
   * <p>
   * This is called when we receive a message with a DH public key
   * different from what we have stored.
   * <p>
   * This is called when we receive a message with a DH public key
   * different from what we have stored.
   */
  public static void dhRatchetStep(RatchetState state, byte[] newRemotePublicKey) {
    throw new UnsupportedOperationException("Implement me!");
  }

  /**
   * Check if we need to perform a DH ratchet step.
   *
   * @param state             current ratchet state
   * @param receivedPublicKey public key from received message
   * @return true if the public key is different (need to ratchet)
   */
  public static boolean needsDHRatchet(RatchetState state, byte[] receivedPublicKey) {
    // TODO: Compare received public key with stored remote public key
    // Use constant-time comparison from CryptoUtils!
    // Return true if they differ or if we don't have a remote key yet

    throw new UnsupportedOperationException("Implement me!");
  }
}