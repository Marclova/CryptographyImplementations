package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.extraction;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.management.openmbean.InvalidKeyException;

public class DSAParametersExtractor extends ParametersExtractor
{
    public DSAParametersExtractor() {};


    /**
     * Extracts parameters from a dsa public Key.
     * The p, q, g and y values, the others will be set to null.
     * 
     * @param key The DSAPublicKey to extract the informations from.
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    @Override
    public void extractFromPublicKey(Key publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (!(publicKey instanceof DSAPublicKey))
        {
            throw new InvalidKeyException("A 'DSAPublicKey' was expected, but received '" + publicKey.getClass() + "' instead.");
        }

        DSAPublicKeySpec keySpec = KeyFactory.getInstance(publicKey.getAlgorithm()).getKeySpec(publicKey, DSAPublicKeySpec.class);
        
        this.extractFromPublicKeySpec(keySpec);
    }

    /**
     * Extracts parameters from a dsa private Key.
     * The p, q, g and x values get updated.
     * 
     * @param key The DSAPrivateKey to extract the informations from.
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    @Override
    public void extractFromPrivateKey(Key privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (!(privateKey instanceof DSAPrivateKey))
        {
            throw new InvalidKeyException("A 'DSAPrivateKey' was expected, but received '" + privateKey.getClass() + "' instead.");
        }

        DSAPrivateKeySpec keySpec = KeyFactory.getInstance(privateKey.getAlgorithm()).getKeySpec(privateKey, DSAPrivateKeySpec.class);
        
        this.extractFromPrivateKeySpec(keySpec);
    }


    /**
     * Extracts parameters from a dsa public Key spec.
     * The p, q, g and y values get updated.
     * 
     * @param key The DSAPublicKeySpec to extract informations from
     */
    @Override
    public void extractFromPublicKeySpec(KeySpec publicKeySpec)
    {
        if (!(publicKeySpec instanceof DSAPublicKeySpec))
        {
            throw new InvalidKeyException("A 'DSAPublicKeySpec' was expected, but received '" + publicKeySpec.getClass() + "' instead.");
        }
        DSAPublicKeySpec dsaPublicKeySpec = (DSAPublicKeySpec) publicKeySpec;
        
        this.setP(dsaPublicKeySpec.getP());
        this.setQ(dsaPublicKeySpec.getQ());
        this.setG(dsaPublicKeySpec.getG());
        this.setY(dsaPublicKeySpec.getY());
    }

    /**
     * Extracts parameters from a dsa private Key spec.
     * The p, q, g and x values get updated.
     * 
     * @param privateKeySpec The DSAPrivateKeySpec to extract informations from
     */
    @Override
    public void extractFromPrivateKeySpec(KeySpec privateKeySpec)
    {
        if (!(privateKeySpec instanceof DSAPrivateKeySpec))
        {
            throw new InvalidKeyException("A 'DSAPrivateKeySpec' was expected, but received '" + privateKeySpec.getClass() + "' instead.");
        }
        DSAPrivateKeySpec dsaPrivateKeySpec = (DSAPrivateKeySpec) privateKeySpec;

        this.setP(dsaPrivateKeySpec.getP());
        this.setQ(dsaPrivateKeySpec.getQ());
        this.setG(dsaPrivateKeySpec.getG());
        this.setX(dsaPrivateKeySpec.getX());
    }


    /**
     * Extracts parameters from a dsa parameter spec.
     *  The p, q, and g values get updated.
     * 
     * @param paramSpec The DSAParameterSpec to extract informations from
     */
    @Override
    public void extractFromParameterSpec(AlgorithmParameterSpec paramSpec)
    {
        if (!(paramSpec instanceof DSAParameterSpec))
        {
            throw new InvalidKeyException("A 'DSAParameterSpec' was expected, but received '" + paramSpec.getClass() + "' instead.");
        }
        DSAParameterSpec dsaParamSpec = (DSAParameterSpec) paramSpec;
        
        this.setP(dsaParamSpec.getP());
        this.setQ(dsaParamSpec.getQ());
        this.setG(dsaParamSpec.getG());
    }
}