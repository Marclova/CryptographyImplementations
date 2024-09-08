package DSAAndECDSAImplementations.Java.libraries.parameters_containers;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class ECParameterSpecExtractor implements AlgorithmParameterSpec{
    
    private BigInteger a;
    private BigInteger b;
    private BigInteger p;
    private BigInteger q;
    private ECPoint g;

    public ECParameterSpecExtractor(BigInteger a, BigInteger b, BigInteger p, BigInteger q, ECPoint g)
    {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public ECParameterSpecExtractor(ECParameterSpec params)
    {
        if (!(params.getCurve().getField() instanceof ECFieldFp))
        {
            throw new UnsupportedOperationException("The private method 'ecPointDouble' has been implemented to work with an 'ECFieldFp' curve, not + "
                                                        + params.getCurve().getField().getClass().toString());
        }

        EllipticCurve eCurve = params.getCurve();

        this.a = eCurve.getA();
        this.b = eCurve.getB();
        this.p = ((ECFieldFp) eCurve.getField()).getP();
        this.q = params.getOrder();
        this.g = params.getGenerator();
    }

    // public ECParameterSpecExtractor(ECPrivateKeyImpl privK)
    // {
        
    // }

    public BigInteger getA()
    {
        return a;
    }

    public BigInteger getB()
    {
        return b;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public ECPoint getG()
    {
        return g;
    }

    @Override
    public String toString()
    {
        return "p:\n" + p + "\nq:\n" + q + "\ng:\n" + g;
    }
}