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

    System.out.println("=== Double Ratchet Demo ===");
    // Step 1: Simulate initial key exchange
    // In practice, this would be X3DH or similar
    System.out.println("1. Simulating initial key exchange...");

    // Bob publishes a prekey
    DHKeyPair bobPrekey = DHKeyPair.generate();
    System.out.println("   Bob's prekey: " +
        CryptoUtils.bytesToHex(bobPrekey.getPublicKeyBytes()).substring(0, 16) + "...");

    // Alice generates ephemeral key and computes shared secret
    DHKeyPair aliceEphemeral = DHKeyPair.generate();
    byte[] sharedSecret = aliceEphemeral.dh(bobPrekey.getPublicKey());
    System.out.println("   Shared secret established: " +
        CryptoUtils.bytesToHex(sharedSecret).substring(0, 16) + "...");

    // Step 2: Initialize Double Ratchet sessions
    System.out.println("\n2. Initializing ratchet sessions...");
    DoubleRatchet alice = new DoubleRatchet();
    alice.initializeAsAlice(sharedSecret, bobPrekey.getPublicKeyBytes());
    System.out.println("   Alice initialized");

    DoubleRatchet bob = new DoubleRatchet();
    bob.initializeAsBob(sharedSecret, bobPrekey);
    System.out.println("   Bob initialized");

    // Step 3: Exchange messages
    System.out.println("\n3. Exchanging messages...\n");

    // Alice sends first message
    String msg1 = "Hello Bob! This is encrypted with Double Ratchet.";
    Message encrypted1 = alice.encrypt(msg1.getBytes(StandardCharsets.UTF_8));
    System.out.println("Alice -> Bob: \"" + msg1 + "\"");

    byte[] decrypted1 = bob.decrypt(encrypted1);
    System.out.println("Bob received: \"" + new String(decrypted1, StandardCharsets.UTF_8) + "\"");

    // Bob replies
    String msg2 = "Hi Alice! Got your message. Replying now.";
    Message encrypted2 = bob.encrypt(msg2.getBytes(StandardCharsets.UTF_8));
    System.out.println("\nBob -> Alice: \"" + msg2 + "\"");

    byte[] decrypted2 = alice.decrypt(encrypted2);
    System.out.println("Alice received: \"" + new String(decrypted2, StandardCharsets.UTF_8) + "\"");

    // Alice sends another (tests symmetric ratchet)
    String msg3 = "Great! Each message uses a different key.";
    Message encrypted3 = alice.encrypt(msg3.getBytes(StandardCharsets.UTF_8));
    System.out.println("\nAlice -> Bob: \"" + msg3 + "\"");

    byte[] decrypted3 = bob.decrypt(encrypted3);
    System.out.println("Bob received: \"" + new String(decrypted3, StandardCharsets.UTF_8) + "\"");

    // Step 4: Test out-of-order delivery
    System.out.println("\n4. Testing out-of-order delivery...\n");

    // Alice sends multiple messages
    Message msgA = alice.encrypt("Message A".getBytes(StandardCharsets.UTF_8));
    Message msgB = alice.encrypt("Message B".getBytes(StandardCharsets.UTF_8));
    Message msgC = alice.encrypt("Message C".getBytes(StandardCharsets.UTF_8));
    System.out.println("Alice sent: A, B, C");

    // Bob receives them out of order: C, A, B
    byte[] gotC = bob.decrypt(msgC);
    System.out.println("Bob got (first): " + new String(gotC, StandardCharsets.UTF_8));

    byte[] gotA = bob.decrypt(msgA);
    System.out.println("Bob got (second): " + new String(gotA, StandardCharsets.UTF_8));

    byte[] gotB = bob.decrypt(msgB);
    System.out.println("Bob got (third): " + new String(gotB, StandardCharsets.UTF_8));

    System.out.println("\n=== Demo Complete ===");
    System.out.println("\nAll messages decrypted successfully!");
    System.out.println("Forward secrecy: Each message used a unique key");
    System.out.println("Break-in recovery: DH ratchet stepped on each reply");
  }
}