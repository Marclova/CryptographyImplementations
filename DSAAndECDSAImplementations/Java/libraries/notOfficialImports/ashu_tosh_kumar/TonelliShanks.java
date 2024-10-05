package DSAAndECDSAImplementations.Java.libraries.notOfficialImports.ashu_tosh_kumar;

import java.math.BigInteger;

public class TonelliShanks {

    /**
     * Main method implementing the Tonelli Shanks algorithm.
     * Tonelli Shanks algorithm:
     * https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
     * 
     * Implementation taken and converted into Java from Python library
     * `pycryptodome`: https://pypi.org/project/pycryptodome/
     * 
     * `Crypto/Math/_IntegerBase.py`. Took help from Claude and ChatGPT and
     * corrected their mistakes by comparing Python and Java code line to line.
     * 
     * @param n: `n` in `r2 ≡ n (mod p)` to find a square root of n modulo p.
     * @param p: `p` in `r2 ≡ n (mod p)` where `p` is prime.
     * @return BigInteger: Returns the required `r` in `r2 ≡ n (mod p)`.
     * @throws IllegalArgumentException
     */
    public static BigInteger tonelliShanks(BigInteger n, BigInteger p) throws IllegalArgumentException {
        if (n.equals(BigInteger.ZERO) || n.equals(BigInteger.ONE)) {
            return n;
        }

        if (p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
            // Compute root for p ≡ 3 (mod 4)
            BigInteger root = n.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
            if (!root.modPow(BigInteger.TWO, p).equals(n)) {
                throw new IllegalArgumentException("Cannot compute square root");
            }
            return root;
        }

        // s is the largest integer such that (p - 1) / 2^s is odd
        BigInteger s = BigInteger.ONE;
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        while (q.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            s = s.add(BigInteger.ONE);
            q = q.shiftRight(1); // Equivalent to q / 2
        }

        // Find a non-residue z
        BigInteger z = BigInteger.TWO;
        while (true) {
            BigInteger euler = z.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p);
            if (euler.equals(BigInteger.ONE)) {
                z = z.add(BigInteger.ONE);
                continue;
            }
            if (euler.equals(p.subtract(BigInteger.ONE))) {
                break;
            }
            // Most probably p is not a prime
            throw new IllegalArgumentException("Cannot compute square root");
        }

        BigInteger m = s;
        BigInteger c = z.modPow(q, p);
        BigInteger t = n.modPow(q, p);
        BigInteger r = n.modPow(q.add(BigInteger.ONE).divide(BigInteger.TWO), p);

        while (!t.equals(BigInteger.ONE)) {
            int i;
            for (i = 0; i < m.intValue(); i++) {
                if (t.modPow(BigInteger.TWO.pow(i), p).equals(BigInteger.ONE)) {
                    break;
                }
            }
            if (i == m.intValue()) {
                throw new IllegalArgumentException("Cannot compute square root of " + n + " mod " + p);
            }

            // Compute b as c^2^(m-i-1) % p
            BigInteger exp = BigInteger.TWO.pow(m.subtract(BigInteger.valueOf(i)).subtract(BigInteger.ONE).intValue());
            BigInteger b = c.modPow(exp, p);

            m = BigInteger.valueOf(i);
            c = b.modPow(BigInteger.TWO, p);
            t = t.multiply(b.modPow(BigInteger.TWO, p));
            r = r.multiply(b).mod(p);
        }

        if (!r.modPow(BigInteger.TWO, p).equals(n)) {
            throw new IllegalArgumentException("Cannot compute square root");
        }

        return r;
    }
}