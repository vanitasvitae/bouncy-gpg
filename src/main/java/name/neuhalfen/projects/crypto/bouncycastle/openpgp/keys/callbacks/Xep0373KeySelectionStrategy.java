package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Key selection strategy that selects keys with a userid in the form of "xmpp:juliet@capulet.lit".
 * It was necessary to overwrite the behaviour of the {@link Rfc4880KeySelectionStrategy}, as that class
 * escaped uids with &lt; and &gt;.
 * This class avoids doing that.
 */
public class Xep0373KeySelectionStrategy extends Rfc4880KeySelectionStrategy {

    /**
     * @param dateOfTimestampVerification The date used for key expiration date checks as "now".
     */
    public Xep0373KeySelectionStrategy(Date dateOfTimestampVerification) {
        super(dateOfTimestampVerification);
    }

    /**
     * Return all keyrings that ARE valid keys for the given uid.
     *
     * Deriving classes can override this.
     *
     * @param uid the userid as passed by upstream.
     * @param keyringConfig the keyring config
     * @param purpose what is the requested key to be used for
     *
     * @return Set with keyrings, never null.
     *
     * @throws PGPException  Something with BouncyCastle went wrong
     * @throws IOException  IO is dangerous
     */
    @SuppressWarnings({"PMD.LawOfDemeter"})
    protected Set<PGPPublicKeyRing> publicKeyRingsForUid(
            final PURPOSE purpose,
            final String uid,
            KeyringConfig keyringConfig)
            throws IOException, PGPException
    {
        Set<PGPPublicKeyRing> keyringsForUid = new HashSet<>();
        final Iterator<PGPPublicKeyRing> keyRings = keyringConfig.getPublicKeyRings()
                .getKeyRings(uid, false, true);

        while (keyRings.hasNext()) {
            keyringsForUid.add(keyRings.next());
        }

        return keyringsForUid;
    }
}
