package doubleratchet.ratchet;

import doubleratchet.crypto.AESCipher;
import doubleratchet.crypto.DHKeyPair;
import doubleratchet.message.Header;
import doubleratchet.message.Message;
import java.security.GeneralSecurityException;

/**
 * Main Double Ratchet protocol implementation.
 *
 * Orchestrates DH ratchet and symmetric ratchet to provide:
 * - End-to-end encryption
 * - Forward secrecy
 * - Break-in recovery
 * - Out-of-order message handling
 *
 * Usage:
 * 1. Aryan and Bhuvana perform initial key exchange (X3DH or similar)
 * 2. Aryan initializes as initiator, Bhuvana as responder
 * 3. Call encrypt() to send, decrypt() to receive
 *
 */
public class DoubleRatchet {

  private final RatchetState state;

  public DoubleRatchet() {
    this.state = new RatchetState();
  }

  /**
   * Initialize as the conversation initiator.
   *
   * @param sharedSecret initial shared secret from key exchange
   * @param remotePublicKey Bhuvana's initial DH public key (prekey)
   */
  public void initializeAsAryan(byte[] sharedSecret, byte[] remotePublicKey) {
    state.initializeAsInitiator(sharedSecret, remotePublicKey);
  }

  /**
   * Initialize as the conversation responder (Bob).
   *
   * @param sharedSecret initial shared secret from key exchange
   * @param ourPrekey Bhuvana's prekey pair that Alice used
   */
  public void initializeAsBhuvana(byte[] sharedSecret, DHKeyPair ourPrekey) {
    state.initializeAsResponder(sharedSecret, ourPrekey);
  }

  /**
   * Encrypt a message.
   *
   * @param plaintext message to encrypt
   * @return encrypted Message
   * @throws GeneralSecurityException on encryption error
   */
  public Message encrypt(byte[] plaintext) throws GeneralSecurityException {
    //
    // 1. Create header with current DH public key and counters
        Header header = new Header(
            state.getDhKeyPair().getPublicKeyBytes(),
            state.getPreviousSendingChainLength(),
            state.getSendingMessageNumber()
        );

    // 2. Advance sending chain to get message key
        byte[] messageKey = SymmetricRatchet.advanceSendingChain(state);

    // 3. Encrypt plaintext with header as associated data
        byte[] ciphertext = AESCipher.encryptWithHeader(
            messageKey, plaintext, header.toBytes()
        );

    // 4. Return complete message
        return new Message(header, ciphertext);
  }

  /**
   * Decrypt a message.
   *
   * @param message encrypted Message
   * @return decrypted plaintext
   * @throws GeneralSecurityException on decryption/auth error
   */
  public byte[] decrypt(Message message) throws GeneralSecurityException {

    // 1. Extract header
        Header header = message.getHeader();
        byte[] theirPublicKey = header.getDhPublicKey();
    // 2. Try to use a skipped message key first
        byte[] skippedKey = state.popSkippedMessageKey(
            theirPublicKey, header.getMessageNumber()
        );
        if (skippedKey != null) {
            return AESCipher.decryptWithHeader(
                skippedKey, message.getCiphertext(), header.toBytes()
            );
        }
    // 3. Check if we need a DH ratchet step
        if (DHRatchet.needsDHRatchet(state, theirPublicKey)) {
            // Skip any remaining message keys in old receiving chain
            if (state.getReceivingChainKey() != null) {
                SymmetricRatchet.skipMessageKeys(state, header.getPreviousChainLength());
            }
            // Perform DH ratchet
            DHRatchet.dhRatchetStep(state, theirPublicKey);
        }

    // 4. Skip ahead if needed for out-of-order messages
        SymmetricRatchet.skipMessageKeys(state, header.getMessageNumber());

    // 5. Advance receiving chain to get message key
        byte[] messageKey = SymmetricRatchet.advanceReceivingChain(state);

    // 6. Decrypt and return
        return AESCipher.decryptWithHeader(
            messageKey, message.getCiphertext(), header.toBytes()
        );

  }

  /**
   * Get our current DH public key.
   * The remote party needs this to send us messages.
   */
  public byte[] getPublicKey() {
    return state.getDhKeyPair().getPublicKeyBytes();
  }
}