package name.neuhalfen.projects.crypto.bouncycastle.openpgp.key_generation;

import static junit.framework.TestCase.assertNotNull;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeySize;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;

public class CreateRSAKeyTest {

    @Test
    public void test() throws PGPException, NoSuchAlgorithmException, IOException, NoSuchProviderException {

        PGPSecretKeyRing secretKeys = BouncyGPG.createKeyPair()
                .withRSAKeys()
                .ofSize(PublicKeySize.RSA._2048)
                .forIdentity("xmpp:test@test.test")
                .withoutPassphrase()
                .build()
                .generateSecretKeyRing();

        assertNotNull(secretKeys);

        File file = new File("/home/vanitas/Schreibtisch/reg.sec");
        if (!file.exists()) {
            file.createNewFile();
        }

        BufferedOutputStream buffered =
                new BufferedOutputStream(new FileOutputStream(file));

        OutputStream outputStream = new ArmoredOutputStream(buffered);

        secretKeys.getSecretKey().encode(outputStream);
        outputStream.close();
        buffered.close();
    }
}
