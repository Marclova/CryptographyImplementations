package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

public class ParametersExtractor implements AlgorithmParameterSpec{
    
    private BigInteger a;
    private BigInteger b;
    private BigInteger p;
    private BigInteger q;
    private Object g;
    private Object y;



    public ParametersExtractor() {};


    public void extractFromKey(PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        DSAPublicKeySpec keySpec = KeyFactory.getInstance(key.getAlgorithm()).getKeySpec(key, DSAPublicKeySpec.class);
        this.extractFromKeySpec(keySpec);
    }

    public void extractFromKeySpec(DSAPublicKeySpec key)
    {
        this.setValues(null, null, key.getP(), key.getQ(), key.getG(), key.getY());
    }

    public void extractFromKeySpec(ECPublicKeySpec key)
    {
        this.setValues(key.getParams(), key.getW());
    }

    public void extractFromParameterSpec(DSAParameterSpec params)
    {
        this.setValues(null, null, params.getP(), params.getQ(), params.getG(), null);
    }

    public void extractFromParameterSpec(ECParameterSpec params)
    {
        if (!(params.getCurve().getField() instanceof ECFieldFp))
        {
            throw new UnsupportedOperationException("The private method 'ecPointDouble' has been implemented to work with an 'ECFieldFp' curve, not + "
                                                        + params.getCurve().getField().getClass().toString());
        }

        this.setValues(params, null);
    }


    //private methods
    private void setValues(ECParameterSpec params, Object y)
    {
        EllipticCurve eCurve = params.getCurve();
        
        this.setValues(eCurve.getA(), eCurve.getB(), ((ECFieldFp) eCurve.getField()).getP(), params.getOrder(), params.getGenerator(), y);
    }

    private void setValues(BigInteger a, BigInteger b, BigInteger p, BigInteger q, Object g, Object y)
    {
        this.a = a;
        this.b = b;
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
    }


    //getters
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

    public Object getG()
    {
        return g;
    }

    public Object getY()
    {
        return y;
    }

    @Override
    public String toString()
    {
        return "p:\n" + p + "\nq:\n" + q + "\ng:\n" + g;
    }
}