package DSAAndECDSAImplementations.Java.libraries.minorUtilities;

import java.math.BigInteger;
import java.security.spec.ECPoint;

public class ECPointConsolePrinter
{
    public String ecPointToString(ECPoint p)
    {
        BigInteger x = p.getAffineX();
        BigInteger y = p.getAffineY();

        if (x.compareTo(new BigInteger(""+Long.MAX_VALUE)) != 1
            && y.compareTo(new BigInteger(""+Long.MAX_VALUE)) != 1)  // if (x <= long_max value && y <= long_max_value)
        {
            return ( "(" + p.getAffineX().longValue() + ", " + p.getAffineY().longValue() + ")" );
        }
        BytesConsolePrinter otherPrinter = new BytesConsolePrinter();
        
        return ( "x:\n" + otherPrinter.byteArrayToString(x.toByteArray()) +
                "\ny:\n" + otherPrinter.byteArrayToString(y.toByteArray()) );
    }
}
