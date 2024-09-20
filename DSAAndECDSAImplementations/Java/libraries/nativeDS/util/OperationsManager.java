package DSAAndECDSAImplementations.Java.libraries.NativeDS.util;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.ParametersCalculator;

public class OperationsManager
{
    private KeyFactory keyFactory;
    private ParametersCalculator pCalculator;
    private Signature signatureManager;
    private SecureRandomNumberGenerator srng;

    public OperationsManager(String KeyPairGeneratorAlgorithmName, String hashAlgorithmName) throws NoSuchAlgorithmException
    {
        this.keyFactory = KeyFactory.getInstance(KeyPairGeneratorAlgorithmName);
        this.pCalculator = ParametersCalculator.simpleGetInstance(KeyPairGeneratorAlgorithmName);
        this.signatureManager = Signature.getInstance(hashAlgorithmName);
        this.srng = new SecureRandomNumberGenerator();
    }

    public OperationsManager(String KeyPairGeneratorAlgorithmName, String hashAlgorithmName, SecureRandom secureRandom) throws NoSuchAlgorithmException
    {
        this.keyFactory = KeyFactory.getInstance(KeyPairGeneratorAlgorithmName);
        this.pCalculator = ParametersCalculator.simpleGetInstance(KeyPairGeneratorAlgorithmName);
        this.signatureManager = Signature.getInstance(hashAlgorithmName);
        this.srng = new SecureRandomNumberGenerator(secureRandom);
    }

    public AlgorithmParameterSpec calculateGValueAndUpdateParamSpec(AlgorithmParameterSpec params)
    {
        return this.pCalculator.calculateGValueAndUpdateParameterSpec(params, this.srng);
    }

    public KeyPair calculateKeyPair(byte[] privateKeyValue, AlgorithmParameterSpec params) throws InvalidKeySpecException
    {
        PrivateKey privateKey = this.keyFactory.generatePrivate(
                                    this.pCalculator.calculatePrivateKeySpec(privateKeyValue, params)
                                );
        PublicKey publicKey = this.keyFactory.generatePublic(pCalculator.calculatePublicKeySpec(privateKeyValue, params));

        return new KeyPair(publicKey, privateKey);
    }

    public byte[] signFile(byte[] file, PrivateKey privateKey)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        this.signatureManager.initSign(privateKey);
        this.signatureManager.update(file);
        
        return signatureManager.sign();
    }

    public boolean verifySignature(byte[] signedFile, byte[] signatureToVerify, PublicKey publicKey)
        throws InvalidKeyException, SignatureException
    {
        this.signatureManager.initVerify(publicKey);
        this.signatureManager.update(signedFile);
        return this.signatureManager.verify(signatureToVerify);
    }
}