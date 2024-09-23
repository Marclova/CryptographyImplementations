package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class ParametersExtractor implements AlgorithmParameterSpec{
    
    private BigInteger a;
    private BigInteger b;
    private BigInteger p;
    private BigInteger q;
    private Object g;
    private Object y;



    public ParametersExtractor() {};

    /**
     * Extracts parameters from a Key.
     *  Afterwards they will be available different values depending on the subtype of the key:
     * -dsa: p, q, g and y
     * -ec: a, b, p, q, g and y
     * 
     * @param key The Key to extract informations from
     * @param <T> The actual type of key in runtime
     * @throws InvalidKeySpecException If the subtype of the key is not supported by the Java.Security
     * @throws NoSuchAlgorithmException If the key's algorithm is not supported by the Java.Security
     */
    public <T extends KeySpec> void extractFromKey(PublicKey key) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        DSAPublicKeySpec keySpec = KeyFactory.getInstance(key.getAlgorithm()).getKeySpec(key, DSAPublicKeySpec.class);
        this.extractFromKeySpec(keySpec);
    }

    /**
     * Extracts parameters from a dsa public Key spec.
     *  Afterwards they will be available the p, q, g and y values.
     * 
     * @param key The DSAPublicKeySpec to extract informations from
     */
    public void extractFromKeySpec(DSAPublicKeySpec key)
    {
        this.setValues(null, null, key.getP(), key.getQ(), key.getG(), key.getY());
    }

    /**
     * Extracts parameters from an ec public Key spec.
     *  Afterwards they will be available the a, b, p, q, g and y values.
     * 
     * @param key The ECPublicKeySpec to extract informations from
     */
    public void extractFromKeySpec(ECPublicKeySpec key)
    {
        this.setValues(key.getParams(), key.getW());
    }

    /**
     * Extracts parameters from a dsa parameter spec.
     *  Afterwards they will be available the p, q, and g values.
     * 
     * @param params The DSAParameterSpec to extract informations from
     */
    public void extractFromParameterSpec(DSAParameterSpec params)
    {
        this.setValues(null, null, params.getP(), params.getQ(), params.getG(), null);
    }

    /**
     * Extracts parameters from an ec parameter spec.
     *  Afterwards they will be available the a, b, p, q, and g values.
     * 
     * @param params The DSAParameterSpec to extract informations from
     */
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