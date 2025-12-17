package doubleratchet.ratchet;

import static doubleratchet.crypto.CryptoUtils.constantTimeEquals;

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

    // 1. Save previous sending chain length (for header)
    state.setPreviousSendingChainLength(state.getSendingMessageNumber());

    // 2. Reset sending and receiving message counters for new chains
    state.setSendingMessageNumber(0);
    state.setReceivingMessageNumber(0);

    // 3. Store the new remote public key
    state.setRemoteDHPublicKey(newRemotePublicKey);

    //4. DH with our current private key and their new public key
    // This derives the new RECEVINg chain
    byte[] dhOutput1 = state.getDhKeyPair().dh(newRemotePublicKey);
    byte[][] kdfResult1 = HKDF.kdfRootKey(state.getRootKey(), dhOutput1);
    state.setRootKey(kdfResult1[0]);
    state.setReceivingChainKey(kdfResult1[1]);

    // 5. Generate NEW DH key pair for our side
    state.setDhKeyPair(DHKeyPair.generate());

    // 6. DH with OUR NEW private key and THEIR public key
    //    This derives the new SENDING chain
    byte[] dhOutput2 = state.getDhKeyPair().dh(newRemotePublicKey);
    byte[][] kdfResult2 = HKDF.kdfRootKey(state.getRootKey(), dhOutput2);
    state.setRootKey(kdfResult2[0]);
    state.setSendingChainKey(kdfResult2[1]);
  }

  /**
   * Check if we need to perform a DH ratchet step.
   *
   * @param state             current ratchet state
   * @param receivedPublicKey public key from received message
   * @return true if the public key is different (need to ratchet)
   */
  public static boolean needsDHRatchet(RatchetState state, byte[] receivedPublicKey) {
    byte[] storedRemoteKey = state.getRemoteDHPublicKey();
    if (storedRemoteKey == null) {
      return true;
    }
    return !constantTimeEquals(storedRemoteKey, receivedPublicKey);
  }
}