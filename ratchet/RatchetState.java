package doubleratchet.ratchet;

import doubleratchet.crypto.DHKeyPair;
import java.util.HashMap;
import java.util.Map;

/**
 * Holds the complete state for a Double Ratchet session.
 *
 * State includes:
 * - DH key pair (ours) and their public key
 * - Root key
 * - Sending and receiving chain keys
 * - Message counters
 * - Skipped message keys (for out-of-order delivery)
 *
 */
public class RatchetState {

  // DH Ratchet state
  private DHKeyPair dhKeyPair;          // Our current DH key pair
  private byte[] remoteDHPublicKey;      // Their current DH public key

  // Symmetric ratchet state
  private byte[] rootKey;                // Current root key (32 bytes)
  private byte[] sendingChainKey;        // Current sending chain key
  private byte[] receivingChainKey;      // Current receiving chain key

  // Message counters
  private int sendingMessageNumber;      // Messages sent in current sending chain
  private int receivingMessageNumber;    // Messages received in current receiving chain
  private int previousSendingChainLength; // Length of previous sending chain

  // Skipped message keys: Map<(dhPublicKey, messageNumber), messageKey>
  // Needed for handling out-of-order messages
  private final Map<SkippedKeyId, byte[]> skippedMessageKeys;

  // Maximum skipped messages to store (prevents DoS)
  private static final int MAX_SKIP = 1000;

  public RatchetState() {
    this.skippedMessageKeys = new HashMap<>();
    this.sendingMessageNumber = 0;
    this.receivingMessageNumber = 0;
    this.previousSendingChainLength = 0;
  }

  /**
   * Initialize state for the initiator (Alice).
   * Alice starts with Bob's prekey and computes initial shared secret.
   *
   * @param sharedSecret initial shared secret (from X3DH or similar)
   * @param remoteDHPublicKey Bob's initial DH public key
   */
  public void initializeAsInitiator(byte[] sharedSecret, byte[] remoteDHPublicKey) {
    // Steps:
    // 1. Generate new DH key pair
    this.dhKeyPair = DHKeyPair.generate();

    // 2. Store remote public key
    this.remoteDHPublicKey = remoteDHPublicKey;

    // 3. Perform initial DH ratchet step:
    //    - DH output = DH(our_private, their_public)
    byte[] dhOutput = dhKeyPair.dh(remoteDHPublicKey);

    //    - (rootKey, sendingChainKey) = KDF_RK(sharedSecret, DH_output)
    KDFResult kdf = KDF_RK(sharedSecret, dhOutput);
    this.rootKey = kdf.rootKey;
    this.sendingChainKey = kdf.chainKey;

    // 4. receivingChainKey stays null until we receive a message
    this.receivingChainKey = null;

    this.sendingMessageNumber = 0;
    this.receivingMessageNumber = 0;
    this.previousSendingChainLength = 0;
  }

  /**
   * Initialize state for the responder (Bob).
   * Bob uses his prekey that Alice used.
   *
   * @param sharedSecret initial shared secret (from X3DH or similar)
   * @param ourDHKeyPair Bob's prekey pair that Alice encrypted to
   */
  public void initializeAsResponder(byte[] sharedSecret, DHKeyPair ourDHKeyPair) {
    if (sharedSecret == null || ourDHKeyPair == null) {
      throw new IllegalArgumentException("Inputs must not be null");
    }
    // 1. Store our DH key pair
    this.dhKeyPair = ourDHKeyPair;

    // 2. Set rootKey to sharedSecret
    this.rootKey = sharedSecret;

    // 3. sendingChainKey and receivingChainKey stay null
    this.sendingChainKey = null;
    this.receivingChainKey = null;

    // 4. remoteDHPublicKey stays null until we receive Alice's first message
    this.sendingMessageNumber = 0;
    this.receivingMessageNumber = 0;
    this.previousSendingChainLength = 0;

  }

  /**
   * Store a skipped message key for later use.
   * Called when we need to skip ahead in the receiving chain.
   *
   * @param dhPublicKey the DH public key for this chain
   * @param messageNumber the message number
   * @param messageKey the message key to store
   */
  public void storeSkippedMessageKey(byte[] dhPublicKey, int messageNumber, byte[] messageKey) {
    if (skippedMessageKeys.size() >= MAX_SKIP) {
      return;
    }
    SkippedKeyId skippedKeyId = new SkippedKeyId(dhPublicKey, messageNumber);
    skippedMessageKeys.put(skippedKeyId, messageKey);
  }

  /**
   * Try to retrieve a skipped message key.
   *
   * @param dhPublicKey the DH public key
   * @param messageNumber the message number
   * @return the message key, or null if not found
   */
  public byte[] popSkippedMessageKey(byte[] dhPublicKey, int messageNumber) {
    SkippedKeyId id = new SkippedKeyId(dhPublicKey, messageNumber);
    return skippedMessageKeys.remove(id);
  }
  }

  // Getters and setters

  public DHKeyPair getDhKeyPair() { return dhKeyPair; }
  public void setDhKeyPair(DHKeyPair dhKeyPair) { this.dhKeyPair = dhKeyPair; }

  public byte[] getRemoteDHPublicKey() { return remoteDHPublicKey; }
  public void setRemoteDHPublicKey(byte[] key) { this.remoteDHPublicKey = key; }

  public byte[] getRootKey() { return rootKey; }
  public void setRootKey(byte[] rootKey) { this.rootKey = rootKey; }

  public byte[] getSendingChainKey() { return sendingChainKey; }
  public void setSendingChainKey(byte[] key) { this.sendingChainKey = key; }

  public byte[] getReceivingChainKey() { return receivingChainKey; }
  public void setReceivingChainKey(byte[] key) { this.receivingChainKey = key; }

  public int getSendingMessageNumber() { return sendingMessageNumber; }
  public void incrementSendingMessageNumber() { this.sendingMessageNumber++; }

  public int getReceivingMessageNumber() { return receivingMessageNumber; }
  public void setReceivingMessageNumber(int n) { this.receivingMessageNumber = n; }
  public void incrementReceivingMessageNumber() { this.receivingMessageNumber++; }

  public int getPreviousSendingChainLength() { return previousSendingChainLength; }
  public void setPreviousSendingChainLength(int n) { this.previousSendingChainLength = n; }

  /**
   * Key for identifying skipped messages.
   */
  private record SkippedKeyId(byte[] dhPublicKey, int messageNumber) {
    // TODO: Override equals and hashCode properly for byte[] comparison
  }
}