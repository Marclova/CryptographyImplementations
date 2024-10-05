package DSAAndECDSAImplementations.Java.libraries.minorUtilities;

import java.math.BigInteger;
import java.security.spec.ECPoint;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.calculation.ECProjectivePoint;

public class ECPointConsolePrinter
{
    BytesConsolePrinter bytesPrinter = new BytesConsolePrinter();

    public String ecPointToString(ECPoint p)
    {
        BigInteger x = p.getAffineX();
        BigInteger y = p.getAffineY();
        
        return ("(" + bytesPrinter.byteArrayToString(x.toByteArray()) + ", " +
                bytesPrinter.byteArrayToString(y.toByteArray()) + ")");
    }

    public String ecPointToString(ECProjectivePoint p)
    {
        BigInteger x = p.getProjectiveX();
        BigInteger y = p.getProjectiveY();
        BigInteger z = p.getProjectiveZ();

        return ("(" + bytesPrinter.byteArrayToString(x.toByteArray()) + ", " +
                    bytesPrinter.byteArrayToString(y.toByteArray()) + ", " +
                    bytesPrinter.byteArrayToString(z.toByteArray()) + ")");
    }
}
