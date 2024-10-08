package DSAAndECDSAImplementations.Java.src.examples;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.extraction.*;
import DSAAndECDSAImplementations.Java.libraries.NativeDS.util.OperationsManager;
import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;
import DSAAndECDSAImplementations.Java.libraries.minorUtilities.ECPointConsolePrinter;

public class StandardParametersMain {
    public static void main(String[] args)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, InvalidKeySpecException
    {
        //defining sample values
        byte[] FileToSign = "Hello World!".getBytes();

        //generic parameters
        String KeyPairGeneratorAlgorithmName;
        String hashAlgorithmName;
        OperationsManager opManager;

        //just to print on console
        BytesConsolePrinter bytePrinter = new BytesConsolePrinter();
        ECPointConsolePrinter ecPrinter = new ECPointConsolePrinter();
        ParametersExtractor extractor;

        //#region choosing algorithm
        short choice = 1;
        switch (choice) {
            case 1:
                KeyPairGeneratorAlgorithmName = "DSA";
                hashAlgorithmName = "SHA256withDSA";
                extractor = new DSAParametersExtractor(); //Just to print on console
                break;

            case 2:
                KeyPairGeneratorAlgorithmName = "EC";
                hashAlgorithmName = "SHA256withECDSA";
                extractor = new ECParametersExtractor(); //Just to print on console
                break;
        
            default:
                throw new IllegalArgumentException("invalid choice");
        }
        //#endregion

        //#region sign application

        //initializing parameters manager
        opManager = new OperationsManager(KeyPairGeneratorAlgorithmName, hashAlgorithmName);

        //generating a random key pair
        KeyPair keyPair = KeyPairGenerator.getInstance(KeyPairGeneratorAlgorithmName).generateKeyPair();

        //applying the file signature
        byte[] generatedSignature = opManager.signFile(FileToSign, keyPair.getPrivate());

        //verifying the file signature
        boolean match = opManager.verifySignature(FileToSign, generatedSignature, keyPair.getPublic());

        //#endregion

        //#region print commands

        extractor.extractFromPublicKey(keyPair.getPublic());
        extractor.extractFromPrivateKey(keyPair.getPrivate());

        BigInteger pValue = extractor.getP();
        BigInteger qValue = extractor.getQ();
        Object gValue = extractor.getG();
        BigInteger xValue = extractor.getX();
        Object yValue = extractor.getY();

        String gStringValue;
        String yStringValue;

        if (gValue instanceof BigInteger)
        {
            gStringValue = ((BigInteger) gValue).toString();
            yStringValue = ((BigInteger) yValue).toString();
        }
        else
        {
            gStringValue = ecPrinter.ecPointToString(((ECPoint) gValue));
            yStringValue = ecPrinter.ecPointToString(((ECPoint) yValue));
        }

        System.out.println("\nSelected algorithm: " + KeyPairGeneratorAlgorithmName + "\n");
        
        System.out.println("selected 'p' module:\n" +
                            pValue.toString() + "\n");
        
        System.out.println("selected 'q' module:\n" +
        qValue.toString() + "\n");

        System.out.println("calculated 'g' generator:\n" +
                            gStringValue + "\n");
        
        System.out.println("chosen private key value:\n" +
                            bytePrinter.byteArrayToString(xValue.toByteArray()) + "\n");

        System.out.println("calculated public key value:\n" +
                            yStringValue + "\n");

        System.out.println("generated signature:\n" + 
                            bytePrinter.byteArrayToString(generatedSignature) + "\n");

        System.out.println("\n- simulating the sending of the buffered signature, the data and public key to the other person -\n");

        System.out.println("Signature match: " + match + "\n");

        //#endregion
    }
}