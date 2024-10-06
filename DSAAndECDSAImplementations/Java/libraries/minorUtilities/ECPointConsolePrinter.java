package DSAAndECDSAImplementations.Java.libraries.minorUtilities;

import java.math.BigInteger;
import java.security.spec.ECPoint;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.calculation.ECProjectivePoint;

public class ECPointConsolePrinter
{

    public String ecPointToString(ECPoint p)
    {
        BigInteger x = p.getAffineX();
        BigInteger y = p.getAffineY();
        
        return ("(" + x.toString() + ", " +
                y.toString() + ")");
    }

    public String ecPointToString(ECProjectivePoint p)
    {
        BigInteger x = p.getProjectiveX();
        BigInteger y = p.getProjectiveY();
        BigInteger z = p.getProjectiveZ();

        return ("(" + x.toString() + ", " +
                    y.toString() + ", " +
                    z.toString() + ")");
    }
}
