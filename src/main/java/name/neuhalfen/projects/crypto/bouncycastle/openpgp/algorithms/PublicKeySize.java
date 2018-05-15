package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

public class PublicKeySize {

    public interface KeySize {
        int getSize();
    }

    public enum RSA implements KeySize {
        _1024(1024),
        _2048(2048),
        _3072(3072),
        _4096(4096),
        _8192(8192)
        ;

        private final int size;

        RSA(int size) {
            this.size = size;
        }

        @Override
        public int getSize() {
            return size;
        }
    }

    public enum DSA_ElGamal implements KeySize {
        _1024(1024),
        _2048(2048),
        _3072(3072)
        ;

        private final int size;

        DSA_ElGamal(int size) {
            this.size = size;
        }

        @Override
        public int getSize() {
            return size;
        }
    }
}
