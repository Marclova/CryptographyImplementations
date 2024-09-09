package DSAAndECDSAImplementations.Java.libraries.native_calculation;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import DSAAndECDSAImplementations.Java.libraries.native_calculation.parameters.ParametersCalculator;

public class OperationsManager
{
    private KeyFactory keyFactory;
    private ParametersCalculator pCalculator;
    private SecureRandomGenerator srg;

    public OperationsManager(String KeyPairGeneratorAlgorithmName) throws NoSuchAlgorithmException
    {
        this.keyFactory = KeyFactory.getInstance(KeyPairGeneratorAlgorithmName);
        this.pCalculator = ParametersCalculator.simpleGetInstance(KeyPairGeneratorAlgorithmName);
        this.srg = new SecureRandomGenerator();
    }

    public OperationsManager(String KeyPairGeneratorAlgorithmName, SecureRandom secureRandom) throws NoSuchAlgorithmException
    {
        this.keyFactory = KeyFactory.getInstance(KeyPairGeneratorAlgorithmName);
        this.pCalculator = ParametersCalculator.simpleGetInstance(KeyPairGeneratorAlgorithmName);
        this.srg = new SecureRandomGenerator(secureRandom);
    }

    public AlgorithmParameterSpec calculateGValueAndUpdateParamSpec(AlgorithmParameterSpec params)
    {
        return this.pCalculator.calculateGValueAndUpdateParameterSpec(params, this.srg);
    }

    public KeyPair calculateKeyPair(byte[] privateKeyValue, AlgorithmParameterSpec params) throws InvalidKeySpecException
    {
        PrivateKey privateKey = this.keyFactory.generatePrivate(
                                    this.pCalculator.calculatePrivateKeySpec(privateKeyValue, params)
                                );
        PublicKey publicKey = this.keyFactory.generatePublic(pCalculator.calculatePublicKeySpec(privateKeyValue, params));

        return new KeyPair(publicKey, privateKey);
    }

    // public byte[] signFile(byte[] file, String hashAlgorithmName)
    // {

    // }
}