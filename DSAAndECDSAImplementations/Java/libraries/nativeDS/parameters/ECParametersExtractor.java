package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.management.openmbean.InvalidKeyException;

public class ECParametersExtractor extends ParametersExtractor
{
    private BigInteger a;
    private BigInteger b;


    public ECParametersExtractor() {};


    /**
     * Extracts parameters from a ec public Key.
     * Afterwards they will be available the p, q, g and y values, the others will be set to null.
     * 
     * @param key The ECPublicKey to extract the informations from.
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    @Override
    public void extractFromPublicKey(Key publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (!(publicKey instanceof ECPublicKey))
        {
            throw new InvalidKeyException("A 'ECPublicKey' was expected, but received '" + publicKey.getClass() + "' instead.");
        }

        ECPublicKeySpec keySpec = KeyFactory.getInstance(publicKey.getAlgorithm()).getKeySpec(publicKey, ECPublicKeySpec.class);
        
        this.extractFromPublicKeySpec(keySpec);
    }

    /**
     * Extracts parameters from a ec private Key.
     * Afterwards they will be available the p, q, g and x values, the others will be set to null.
     * 
     * @param key The ECPrivateKey to extract the informations from.
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    @Override
    public void extractFromPrivateKey(Key privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (!(privateKey instanceof ECPrivateKey))
        {
            throw new InvalidKeyException("A 'ECPrivateKey' was expected, but received '" + privateKey.getClass() + "' instead.");
        }

        ECPrivateKeySpec keySpec = KeyFactory.getInstance(privateKey.getAlgorithm()).getKeySpec(privateKey, ECPrivateKeySpec.class);
        
        this.extractFromPrivateKeySpec(keySpec);
    }


    /**
     * Extracts parameters from a ec public Key spec.
     * Afterwards they will be available the p, q, g and y values, the others will be set to null.
     * 
     * @param key The ECPublicKeySpec to extract informations from
     */
    @Override
    public void extractFromPublicKeySpec(KeySpec publicKeySpec)
    {
        if (!(publicKeySpec instanceof ECPublicKeySpec))
        {
            throw new InvalidKeyException("A 'ECPublicKeySpec' was expected, but received '" + publicKeySpec.getClass() + "' instead.");
        }
        ECPublicKeySpec ecPublicKeySpec = (ECPublicKeySpec) publicKeySpec;
        ECParameterSpec ecParamSpec = ecPublicKeySpec.getParams();
        
        this.extractFromParameterSpec(ecParamSpec); //sets p, q and g
        this.setY(ecPublicKeySpec.getW());
    }

    /**
     * Extracts parameters from a ec private Key spec.
     * Afterwards they will be available the p, q, g and x values, the others will be set to null.
     * 
     * @param privateKeySpec The ECPrivateKeySpec to extract informations from
     */
    @Override
    public void extractFromPrivateKeySpec(KeySpec privateKeySpec)
    {
        if (!(privateKeySpec instanceof ECPrivateKeySpec))
        {
            throw new InvalidKeyException("A 'ECPrivateKeySpec' was expected, but received '" + privateKeySpec.getClass() + "' instead.");
        }
        ECPrivateKeySpec ecPrivateKeySpec = (ECPrivateKeySpec) privateKeySpec;
        ECParameterSpec ecParamSpec = ecPrivateKeySpec.getParams();
        
        this.extractFromParameterSpec(ecParamSpec); //sets p, q and g
        this.setX(ecPrivateKeySpec.getS());
    }


    /**
     * Extracts parameters from a ec parameter spec.
     *  Afterwards they will be available the p, q, and g values.
     * 
     * @param paramSpec The ECParameterSpec to extract informations from
     */
    @Override
    public void extractFromParameterSpec(AlgorithmParameterSpec paramSpec)
    {
        if (!(paramSpec instanceof ECParameterSpec))
        {
            throw new InvalidKeyException("A 'ECParameterSpec' was expected, but received '" + paramSpec.getClass() + "' instead.");
        }
        ECParameterSpec ecParamSpec = (ECParameterSpec) paramSpec;
        EllipticCurve ellipticCurve = ecParamSpec.getCurve();

        if (!(ellipticCurve.getField() instanceof ECFieldFp))
        {
            throw new UnsupportedOperationException("The private method 'ecPointDouble' has been implemented to work with an 'ECFieldFp' curve, not + "
                                                        + ellipticCurve.getField().getClass());
        }

        this.setA(ellipticCurve.getA());
        this.setB(ellipticCurve.getB());
        this.setP(((ECFieldFp) ellipticCurve.getField()).getP());
        this.setQ(ecParamSpec.getOrder());
        this.setG(ecParamSpec.getGenerator());
    }

    //setters
    public void setA(BigInteger a)
    {
        this.a = a;
    }

    public void setB(BigInteger b)
    {
        this.b = b;
    }

    //getters
    public BigInteger getA()
    {
        return this.a;    
    }
    
    public BigInteger getB()
    {
        return this.b;
    }
}