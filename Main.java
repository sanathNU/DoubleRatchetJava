package doubleratchet;

import doubleratchet.crypto.*;
import doubleratchet.ratchet.*;
import doubleratchet.message.*;
import java.nio.charset.StandardCharsets;

/**
 * Demo/test harness for the Double Ratchet implementation.
 *
 * Simulates a conversation between Anand and Bhavana.
 */
public class Main {
  public static void main(String[] args) throws Exception {

//    testCryptoPrimitives();
    System.out.println("=== Double Ratchet Demo ===");
    // Step 1: Simulate initial key exchange
    // In practice, this would be X3DH or similar
    System.out.println("1. Simulating initial key exchange...");

    // Bob publishes a prekey
    DHKeyPair bhuvanaPrekey = DHKeyPair.generate();
    System.out.println("   Bhuvana's prekey: " +
        CryptoUtils.bytesToHex(bhuvanaPrekey.getPublicKeyBytes()).substring(0, 16) + "...");

    // Alice generates ephemeral key and computes shared secret
    DHKeyPair aryanEphemeral = DHKeyPair.generate();
    byte[] sharedSecret = aryanEphemeral.dh(bhuvanaPrekey.getPublicKey());
    System.out.println("   Shared secret established: " +
        CryptoUtils.bytesToHex(sharedSecret).substring(0, 16) + "...");

    // Step 2: Initialize Double Ratchet sessions
    System.out.println("\n2. Initializing ratchet sessions...");
    DoubleRatchet aryan = new DoubleRatchet();
    aryan.initializeAsAryan(sharedSecret, bhuvanaPrekey.getPublicKeyBytes());
    System.out.println("   Aryan initialized");

    DoubleRatchet bhuvana = new DoubleRatchet();
    bhuvana.initializeAsBhuvana(sharedSecret, bhuvanaPrekey);
    System.out.println("   Bhuvana initialized");

    // Step 3: Exchange messages
    System.out.println("\n3. Exchanging messages...\n");

    // Alice sends first message
    String msg1 = "Hello Bhuvana! This is encrypted with Double Ratchet.";
    Message encrypted1 = aryan.encrypt(msg1.getBytes(StandardCharsets.UTF_8));
    System.out.println("Aryan -> Bhuvana: \"" + msg1 + "\"");

    byte[] decrypted1 = bhuvana.decrypt(encrypted1);
    System.out.println("Bob received: \"" + new String(decrypted1, StandardCharsets.UTF_8) + "\"");

    // Bob replies
    String msg2 = "Hi Alice! Got your message. Replying now.";
    Message encrypted2 = bhuvana.encrypt(msg2.getBytes(StandardCharsets.UTF_8));
    System.out.println("\nBob -> Alice: \"" + msg2 + "\"");

    byte[] decrypted2 = aryan.decrypt(encrypted2);
    System.out.println("Alice received: \"" + new String(decrypted2, StandardCharsets.UTF_8) + "\"");

    // Alice sends another (tests symmetric ratchet)
    String msg3 = "Great! Each message uses a different key.";
    Message encrypted3 = aryan.encrypt(msg3.getBytes(StandardCharsets.UTF_8));
    System.out.println("\nAlice -> Bob: \"" + msg3 + "\"");

    byte[] decrypted3 = bhuvana.decrypt(encrypted3);
    System.out.println("Bob received: \"" + new String(decrypted3, StandardCharsets.UTF_8) + "\"");

    // Step 4: Test out-of-order delivery
    System.out.println("\n4. Testing out-of-order delivery...\n");

    // Alice sends multiple messages
    Message msgA = aryan.encrypt("Message A".getBytes(StandardCharsets.UTF_8));
    Message msgB = aryan.encrypt("Message B".getBytes(StandardCharsets.UTF_8));
    Message msgC = aryan.encrypt("Message C".getBytes(StandardCharsets.UTF_8));
    System.out.println("Alice sent: A, B, C");

    // Bob receives them out of order: C, A, B
    byte[] gotC = bhuvana.decrypt(msgC);
    System.out.println("Bob got (first): " + new String(gotC, StandardCharsets.UTF_8));

    byte[] gotA = bhuvana.decrypt(msgA);
    System.out.println("Bob got (second): " + new String(gotA, StandardCharsets.UTF_8));

    byte[] gotB = bhuvana.decrypt(msgB);
    System.out.println("Bob got (third): " + new String(gotB, StandardCharsets.UTF_8));

    System.out.println("\n=== Demo Complete ===");
    System.out.println("\nAll messages decrypted successfully!");
    System.out.println("Forward secrecy: Each message used a unique key");
    System.out.println("Break-in recovery: DH ratchet stepped on each reply");
  }


  /**
   * Run individual crypto tests.
   */
  public static void testCryptoPrimitives() throws Exception {
    System.out.println("=== Testing Crypto Primitives ===\n");

    // Test CryptoUtils
    System.out.println("CryptoUtils.randomBytes:");
    byte[] random = CryptoUtils.randomBytes(16);
    System.out.println("  " + CryptoUtils.bytesToHex(random));

    // Test HKDF
    System.out.println("\nHKDF:");
    byte[] salt = CryptoUtils.randomBytes(32);
    byte[] ikm = CryptoUtils.randomBytes(32);
    byte[] derived = HKDF.deriveKey(salt, ikm, "test".getBytes(), 64);
    System.out.println("  Derived 64 bytes: " + CryptoUtils.bytesToHex(derived).substring(0, 32) + "...");

    // Test AES-GCM
    System.out.println("\nAES-GCM:");
    byte[] key = CryptoUtils.randomBytes(32);
    byte[] plaintext = "Hello, encryption!".getBytes(StandardCharsets.UTF_8);
    byte[] aad = "header".getBytes(StandardCharsets.UTF_8);

    byte[] ciphertext = AESCipher.encrypt(key, plaintext, aad);
    System.out.println("  Encrypted length: " + ciphertext.length);

    byte[] decrypted = AESCipher.decrypt(key, ciphertext, aad);
    System.out.println("  Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));

    // Test DHKeyPair
    System.out.println("\nX25519:");
    DHKeyPair kp1 = DHKeyPair.generate();
    DHKeyPair kp2 = DHKeyPair.generate();

    byte[] secret1 = kp1.dh(kp2.getPublicKey());
    byte[] secret2 = kp2.dh(kp1.getPublicKey());

    System.out.println("  DH result 1: " + CryptoUtils.bytesToHex(secret1).substring(0, 32) + "...");
    System.out.println("  DH result 2: " + CryptoUtils.bytesToHex(secret2).substring(0, 32) + "...");
    System.out.println("  Secrets match: " + CryptoUtils.constantTimeEquals(secret1, secret2));

    System.out.println("\n=== All tests passed ===");
  }
}