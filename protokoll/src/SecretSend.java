import java.util.*;
import java.math.*;

class SecretSend {

    // We use random values here and there...
    private static final Random rand = new Random();

    final int bitlen;

    // The initial prefix length.
    final int k, twoToK;
    // The current prefix length.
    int k2;

    // The (index of the) currently prefix proper.
    int cur;

    // Private counter. Counter for money. Even the old songs will do~
    // This counts how many y() calls there have been since the last nextRound().
    private int counter;

    // Arrr! This is the backing array.
    BigInteger[] arr;

    // Word. To check against.
    BigInteger word;

    public SecretSend(BigInteger word, int k, int bitlen) {
        this.k2 = this.k = k;
        this.twoToK = (int) Math.pow(2, k);
        this.bitlen = bitlen;
        this.word = word;

        this.counter = 0;

        arr = new BigInteger[(int) Math.pow(2, k+1)];
        BigInteger prefix = word.shiftRight(word.bitLength()-k2);
        cur = -1;
        for(int i = 0; i < arr.length; i++) {
            arr[i] = BigInteger.valueOf(i);
            if(arr[i].equals(prefix))
                cur = i;
        }
        assert(cur != -1 && arr[cur].equals(prefix)) : "Prefix not found in initial backing array!";
    }

    /// Increases the prefix length by 1, and calculates new backing array.
    // This method should (and can) only be called if y() has been called
    // exactly this.k/2 times since the last call to nextRound()!
    public void nextRound() {

        assert(this.counter == twoToK) : "Tried to call nextRound() without calling y() exactly 2^k times first!";
        assert(this.counter != -1) : "Tried to call nextRound() after call to yOverride()!";

        this.k2 += 1;
        this.counter = 0;
        // This will be reinitialized later on.
        this.cur = -1;

        // The prefix to check against for the new value of cur.
        BigInteger prefix = word.shiftRight(word.bitLength()-k2);

        BigInteger[] arr2 = new BigInteger[arr.length];
        int j = 0;
        for(int i = 0; i < arr.length; i++) {
            if(arr[i] == null)
                continue;

            arr2[j] = arr[i].shiftLeft(1);
            if(arr2[j].equals(prefix))
                cur = j;
            j += 1;

            arr2[j] = arr[i].shiftLeft(1).setBit(0);
            if(arr2[j].equals(prefix))
                cur = j;
            j += 1;

        }
        // We should have exactly arr.length places filled (no nulls left!)
        assert(j == arr.length) : "Backing array not completely filled!";
        arr = arr2;
        assert(cur != -1 && arr[cur].equals(prefix)) : "Prefix not marked for next round!";

    }

    /// Returns a random index, which is neither the prefix, nor stil in the backing array.
    public int y() {

        // Before anything else, check if we have not yet returned more than half the array!
        assert(this.counter < twoToK) : "Tried to call y() more than 2^k times between rounds!";

        this.counter += 1;

        // Pick random, remove from array, return index.
        while(true) {
            int i = rand.nextInt(arr.length);
            if(i == cur || arr[i] == null)
                continue;
            arr[i] = null;
            return i;
        }

    }

    /// Returns more ys, non-randomly and regardless of stuff.
    // There cannot be any more calls to nextRound() after this method has been used!
    public int yOverride() {
        this.counter = -1;

        for(int i = 0; i < arr.length; i++) {
            if(i == cur || arr[i] == null)
                continue;
            arr[i] = null;
            return i;
        }

        assert(false) : "Tried to get y with empty backing array (ie, only prefix left)!";
        return 0;
    }

}
