package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

@SuppressWarnings({"PMD.AtLeastOneConstructor","PMD.AccessorMethodGeneration","PMD.LawOfDemeter"})
public final class BouncyGPG {

  private BouncyGPG() {
  }

  /**
   * Entry point for stream based decryption.  Ultimately an encryption output stream is placed
   * before a user supplied output stream so that plaintext written to the encryption stream is
   * encrypted and written to the user supplied output stream. . Example:
   * https://github.com/neuhalje/bouncy-gpg/tree/master/examples/decrypt . Usage: . final
   * OutputStream encryptionStream = BouncyGPG .encryptToStream() .withConfig(Configs.keyringConfigFromFilesForSender())
   * .withDefaultAlgorithms() .toRecipient("recipient@example.com") .andSignWith("sender@example.com")
   * .armorAsciiOutput() .andWriteTo(cipherText); <p> encryptionStream.write(expectedPlaintext);
   * encryptionStream.close(); cipherText.close(); .
   *
   * @return The next build step. In the end the encryption stream.
   */
  public static BuildDecryptionInputStreamAPI decryptAndVerifyStream() {
    return new BuildDecryptionInputStreamAPI();
  }

  /**
   * Entry point for stream based encryption.  Ultimately a decrypting input stream is placed before
   * a user supplied stream with encrypted data. . Example: https://github.com/neuhalje/bouncy-gpg/tree/master/examples/encrypt
   * .
   *
   * @return The next build step. In the end the decryption stream.
   */
  public static BuildEncryptionOutputStreamAPI encryptToStream() {
    return new BuildEncryptionOutputStreamAPI();
  }

  /**
   * Entry point for creating a fresh OpenPGP key.
   *
   * @return the next build step.
   */
  public static BuildPGPKeyGeneratorAPI createKeyPair() {
    return new BuildPGPKeyGeneratorAPI();
  }

  /**
   * Remove any registered Provider using the "BC" name.
   * Then register the {@link BouncyCastleProvider}.
   * This procedure makes it possible to use BC on older Android devices that ship their own BC implementation.
   */
  public static void registerProvider() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.addProvider(new BouncyCastleProvider());
  }
}
