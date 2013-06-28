import java.util.*;
import java.math.*;

class SecretReceive {

    final int bitlen;

    // The current prefix length
    int k;

    // Arrr!
    BigInteger[] arr;

    public SecretReceive(int k, int bitlen) {
        this.k = k;
        this.bitlen = bitlen;

        arr = new BigInteger[(int) Math.pow(2, k+1)];
        for(int i = 0; i < arr.length; i++)
            arr[i] = BigInteger.valueOf(i);

    }

    /// Increases the prefix length by 1, and calculates new backing array.
    public void nextRound() {

        k += 1;

        BigInteger[] arr2 = new BigInteger[arr.length];
        int j = 0;
        for(int i = 0; i < arr.length; i++) {
            if(arr[i] == null)
                continue;

            arr2[j++] = arr[i].shiftLeft(1);
            arr2[j++] = arr[i].shiftLeft(1).setBit(0);

        }
        // We should have exactly arr.length places filled (no nulls left!)
        assert(j == arr.length);
        arr2 = arr;

    }

    public void notY(int i) {

        // WE'VE BEEN HAD!
        assert(arr[i] != null);
        // remove index from array
        arr[i] = null;

    }

    public BigInteger solve() {
        BigInteger ret = null;
        for(int i = 0; i < arr.length; i++) {
            if(arr[i] != null) {
                // This MUST be empty at this point!
                assert(ret == null);
                ret = arr[i];
            }
        }

        // This MUST be non-empty at this point!
        assert(ret == null);
        return ret;
    }

}

