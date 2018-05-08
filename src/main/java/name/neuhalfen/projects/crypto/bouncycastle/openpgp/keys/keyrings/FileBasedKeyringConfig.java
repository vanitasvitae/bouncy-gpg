package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;

/**
 * Load keyrings from files. These files are created and managed via gpg.
 */
final class FileBasedKeyringConfig extends AbstractDefaultKeyringConfig {

  @Nonnull
  private final File publicKeyring;
  @Nonnull
  private final File secretKeyring;

  public FileBasedKeyringConfig(@Nonnull KeyringConfigCallback callback,
      @Nonnull File publicKeyring, @Nonnull File secretKeyring) {
    super(callback);
    this.publicKeyring = publicKeyring;
    this.secretKeyring = secretKeyring;
  }

  @Nonnull
  @Override
  protected InputStream getPublicKeyRingStream() throws IOException {
    return new FileInputStream(publicKeyring);
  }

  @Nonnull
  @Override
  protected InputStream getSecretKeyRingStream() throws IOException {
    return new FileInputStream(secretKeyring);
  }
}
