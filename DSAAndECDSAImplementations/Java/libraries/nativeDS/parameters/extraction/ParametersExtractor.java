package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.extraction;

import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public abstract class ParametersExtractor implements AlgorithmParameterSpec
{
    private BigInteger p;
    private BigInteger q;
    private Object g;
    private BigInteger x;
    private Object y;

    /**
     * Extracts parameters from a public Key.
     * Some values will be updated depending on the subclass implementing this method.
     * 
     * @param key The Key to extract the informations from.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public abstract void extractFromPublicKey(Key publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException;

    /**
     * Extracts parameters from a private Key.
     * Some values will be updated depending on the subclass implementing this method.
     * 
     * @param key The Key to extract the informations from.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public abstract void extractFromPrivateKey(Key privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException;

    /**
     * Extracts parameters from a public Key spec.
     * Some values will be updated depending on the subclass implementing this method.
     * 
     * @param keySpec The KeySpec to extract informations from
     */
    public abstract void extractFromPublicKeySpec(KeySpec publicKeySpec);
    
    /**
     * Extracts parameters from a private Key spec.
     * Some values will be updated depending on the subclass implementing this method.
     * 
     * @param keySpec The KeySpec to extract informations from
     */
    public abstract void extractFromPrivateKeySpec(KeySpec privateKeySpec);

    /**
     * Extracts parameters from a parameter spec.
     * Some values will be updated depending on the subclass implementing this method.
     * 
     * @param params The DSAParameterSpec to extract informations from
     */
    public abstract void extractFromECFieldFpParameterSpec(AlgorithmParameterSpec params);

    //setters    
    public void setP(BigInteger p)
    {
        this.p = p;
    }
    
    public void setQ(BigInteger q)
    {
        this.q = q;
    }
    
    public void setG(Object g)
    {
        this.g = g;
    }
    
    public void setX(BigInteger x)
    {
        this.x = x;
    }
    
    public void setY(Object y)
    {
        this.y = y;
    }

    //getters    
    public BigInteger getP()
    {
        return this.p;
    }
    
    public BigInteger getQ()
    {
        return this.q;
    }
    
    public Object getG()
    {
        return this.g;
    }
    
    public BigInteger getX()
    {
        return this.x;
    }

    public Object getY()
    {
        return this.y;
    }
}