package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.calculation;

import java.math.BigInteger;
import java.security.spec.ECPoint;

public class ECProjectivePoint extends ECPoint implements Cloneable
{
    private final BigInteger z;

    public static final ECProjectivePoint POINT_AT_INFINITY = new ECProjectivePoint(BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);

    public ECProjectivePoint(BigInteger x, BigInteger y, BigInteger z)
    {
        super(x, y);
        if (z == null)
        {
            this.z = BigInteger.ONE;
        }
        else
        {
            this.z = z;
        }
    }

    public ECProjectivePoint(BigInteger x, BigInteger y)
    {
        super(x, y);
        this.z = BigInteger.ONE;
    }

    public ECProjectivePoint(ECPoint affinePoint)
    {
        this(affinePoint.getAffineX(), affinePoint.getAffineY());
    }

    public ECProjectivePoint(ECProjectivePoint projectivePoint)
    {
        this(projectivePoint.getProjectiveX(), projectivePoint.getProjectiveY(), projectivePoint.getProjectiveZ());
    }


    public boolean isPointToInfinity()
    {
        return (this.z.compareTo(BigInteger.ZERO) == 0); //return z == 0
    }

    //getters
    public BigInteger getProjectiveX()
    {
        return this.getAffineX();
    }

    public BigInteger getProjectiveY()
    {
        return this.getAffineY();
    }

    public BigInteger getProjectiveZ()
    {
        return this.z;
    }

    public BigInteger getAffineXMod(BigInteger field)
    {
        return this.getAffineX().multiply(
                                    z.modInverse(field)
                                ).mod(field);
    }

    public BigInteger getAffineYMod(BigInteger field)
    {
        return this.getAffineY().multiply(
                                    z.modInverse(field)
                                ).mod(field);
    }


    public ECProjectivePoint clone() //It looks like python! (I hate python)
    {
        return new ECProjectivePoint(this);
    }

    @Override
    public boolean equals(Object o)
    {
        if (o == null || !(o instanceof ECPoint)) return false;
        if (this == o) return true;

        ECProjectivePoint ecPO = new ECProjectivePoint((ECPoint) o);

        if (this.isPointToInfinity() && ecPO.isPointToInfinity()) return true;

        return ((this.getProjectiveX().compareTo(ecPO.getProjectiveX()) == 0) &&
                (this.getProjectiveY().compareTo(ecPO.getProjectiveY()) == 0) &&
                (this.getProjectiveZ().compareTo(ecPO.getProjectiveZ()) == 0));
    }

    @Override
    public int hashCode()
    {
        if (this.isPointToInfinity()) return 0;
        return this.getAffineX().hashCode() << 5 + this.getAffineY().hashCode() << 7 + this.z.hashCode();
    }
}
