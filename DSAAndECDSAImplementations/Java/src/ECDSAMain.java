package DSAAndECDSAImplementations.Java.src;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;

public class ECDSAMain {
    public static void main(String[] args)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException
    {
        //defining sample values
        byte[] FileToSign = "Hello World!".getBytes();

        //standard names
        String standardCurveName = "secp256r1";
        String KeyPairGeneratorAlgorithmName = "EC";
        String hashAlgorithmName = "SHA256withECDSA";
        
        //initialing a standard curve with standard parameters (I don't know those values)
        ECGenParameterSpec parameters = new ECGenParameterSpec(standardCurveName);

        KeyPairGenerator kPairGen = KeyPairGenerator.getInstance(KeyPairGeneratorAlgorithmName);
        kPairGen.initialize(parameters);

        //generating a random key pair
        KeyPair kPair = kPairGen.generateKeyPair();
        PrivateKey privateKey = kPair.getPrivate();
        PublicKey publicKey = kPair.getPublic();

        //applying the file signature
        Signature sign = Signature.getInstance(hashAlgorithmName);
        sign.initSign(privateKey);
        sign.update(FileToSign);
        byte[] generatedSignature = sign.sign();
        //The generated signature is already in a proper format to be sent

        //verifying the file signature
        Signature verify = Signature.getInstance(hashAlgorithmName);
        verify.initVerify(publicKey);
        verify.update(FileToSign);
        boolean match = verify.verify(generatedSignature);

        // - - - - - - - - - - - - - - - - - - - - -

        //#region print commands

        BytesConsolePrinter cPrinter = new BytesConsolePrinter();
        
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