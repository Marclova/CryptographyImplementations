package DSAAndECDSAImplementations.Java.src.examples;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;

public class StandardParametersMain {
    public static void main(String[] args)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException
    {
        //defining sample values
        byte[] FileToSign = "Hello World!".getBytes();

        //generic parameters
        String KeyPairGeneratorAlgorithmName;
        String hashAlgorithmName;

        //standard names
        switch (1) {
            case 1:
                KeyPairGeneratorAlgorithmName = "DSA";
                hashAlgorithmName = "SHA256withDSA";
                break;

            case 2:
                KeyPairGeneratorAlgorithmName = "EC";
                hashAlgorithmName = "SHA256withECDSA";
                break;
        
            default:
                throw new IllegalArgumentException("invalid choice");
        }


        KeyPairGenerator kPairGen = KeyPairGenerator.getInstance(KeyPairGeneratorAlgorithmName);

        //generating a random key pair
        KeyPair kPair = kPairGen.generateKeyPair();
        PrivateKey privateKey = kPair.getPrivate();
        PublicKey publicKey = kPair.getPublic();

        //applying the file signature
        Signature sign = Signature.getInstance(hashAlgorithmName);
        sign.initSign(privateKey);
        sign.update(FileToSign);
        byte[] generatedSignature = sign.sign();

        //verifying the file signature
        Signature verify = Signature.getInstance(hashAlgorithmName);
        verify.initVerify(publicKey);
        verify.update(FileToSign);
        boolean match = verify.verify(generatedSignature);

        // - - - - - - - - - - - - - - - - - - - - -

        //#region print commands

        BytesConsolePrinter cPrinter = new BytesConsolePrinter();
        
        System.out.println("Selected algorithm: " + KeyPairGeneratorAlgorithmName + "\n");
        
        System.out.println("\nextracted private key value:\n" +
                            cPrinter.byteArrayToString(privateKey.getEncoded()) + "\n");
        
        System.out.println("calculated public key value:\n" +
                            cPrinter.byteArrayToString(publicKey.getEncoded()) + "\n");

        System.out.println("generated signature:\n" +
                            cPrinter.byteArrayToString(generatedSignature) + "\n");

        System.out.println("Signature match: " + match + "\n");

        //#endregion
    }
}