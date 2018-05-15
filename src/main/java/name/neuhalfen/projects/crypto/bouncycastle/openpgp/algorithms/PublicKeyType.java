package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public enum PublicKeyType {
    RSA_GENERAL(    PublicKeyAlgorithmTags.RSA_GENERAL,     "RSA"),
    @Deprecated
    RSA_ENCRYPT(    PublicKeyAlgorithmTags.RSA_ENCRYPT,     "RSA"),
    @Deprecated
    RSA_SIGN(       PublicKeyAlgorithmTags.RSA_SIGN,        "RSA"),
    ELGAMAL_ENCRYPT(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, "ElGamal"),
    DSA(            PublicKeyAlgorithmTags.DSA,             "DSA"),
    @Deprecated
    EC(             PublicKeyAlgorithmTags.EC,              "EC"),
    ECDH(           PublicKeyAlgorithmTags.ECDH,            "ECDH"),
    ECDSA(          PublicKeyAlgorithmTags.ECDSA,           "ECDSA"),
    ELGAMAL_GENERAL(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ElGamal"),
    DIFFIE_HELLMAN( PublicKeyAlgorithmTags.DIFFIE_HELLMAN,  "DiffieHellman")
    ;

    private static final Map<Integer, PublicKeyType> MAP = new HashMap<>();

    static {
        for (PublicKeyType a : PublicKeyType.values()) {
            MAP.put(a.getId(), a);
        }
    }

    private final int rfc4880_ID;
    private final String algorithmName;

    PublicKeyType(int typeId, String algoName) {
        this.rfc4880_ID = typeId;
        this.algorithmName = algoName;
    }

    public static PublicKeyType fromId(int typeId) {
        PublicKeyType algorithm = MAP.get(typeId);
        if (algorithm == null) {
            throw new IllegalArgumentException("Unknown id: " + typeId);
        }
        return algorithm;
    }

    public int getId() {
        return rfc4880_ID;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

}
