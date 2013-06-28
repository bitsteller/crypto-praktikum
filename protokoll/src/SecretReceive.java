import java.util.*;
import java.math.*;

class SecretReceive {

    // The current prefix length
    int k;

    // Arrr!
    BigInteger[] arr;

    public SecretReceive(int k) {
        this.k = k;

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
        assert(j == arr.length) : "Backing array not completely filled in!";
        arr = arr2;

    }

    public void notY(int i) {

        // WE'VE BEEN HAD!
        assert(arr[i] != null) : "Tried to remove one element twice!";
        // remove index from array
        arr[i] = null;

    }

    public BigInteger solve() {
        BigInteger ret = null;
        for(int i = 0; i < arr.length; i++) {
            if(arr[i] != null) {
                // This MUST be empty at this point!
                assert(ret == null) : "More than one value left, cannot solve (more notY() calls needed)!";
                ret = arr[i];
            }
        }

        // This MUST be non-empty at this point!
        assert(ret != null) : "No value left to return! (should never happen)";
        return ret;
    }

    public static void main(String[] args) {
        BigInteger secwet = new BigInteger("1234");
        System.out.println("in: " + secwet.toString(2));
        System.out.println();

        int bitlen = secwet.bitLength();
        bitlen += 3;
        int k = 3, k2 = 3;

        SecretSend s = new SecretSend(secwet, k, bitlen);
        SecretReceive r = new SecretReceive(k);

        while(true) {
            for(int i = 0; i < Math.pow(2, k); i++) {
                int y = s.y();
                r.notY(y);
            }

            if(k2 == bitlen)
                break;

            System.out.println("next round: " + k2);

            System.out.print("receive: ");
            for(int i = 0; i < r.arr.length; i++) {
                if(r.arr[i] == null)
                    System.out.print("NULL, ");
                else
                    System.out.print(r.arr[i].toString(2) + ", ");
            }
            System.out.println();

            System.out.print("send: ");
            for(int i = 0; i < s.arr.length; i++) {
                if(s.arr[i] == null)
                    System.out.print("NULL, ");
                else {
                    if(s.cur == i)
                        System.out.print("[" + s.arr[i].toString(2) + "], ");
                    else
                        System.out.print(s.arr[i].toString(2) + ", ");
                }
            }
            System.out.println();

            s.nextRound();
            r.nextRound();


            k2 += 1;
        }

        System.out.println("giving " + (int) (Math.pow(2, k)-1) + " additional bits...");
        for(int i = 0; i < Math.pow(2, k)-1; i++) {
            int y = s.yOverride();
            r.notY(y);
        }

        System.out.println();
        System.out.println("done! last element left: " + r.solve().toString(2));

    }

    public void debug() {
        System.out.print("receive: ");
        for(int i = 0; i < arr.length; i++) {
            if(arr[i] == null)
                System.out.print("NULL, ");
            else
                System.out.print(arr[i].toString(2) + ", ");
        }
        System.out.println();
    }

}

