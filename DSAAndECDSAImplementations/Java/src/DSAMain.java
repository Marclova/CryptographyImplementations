package DSAAndECDSAImplementations.Java.src;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class DSAMain {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] byteMessage = "Hello World!".getBytes();

        System.out.println("Digital Signature Algorithm (DSA)");
        System.out.println();

        KeyPairGenerator kPairGen = KeyPairGenerator.getInstance("DSA");
        kPairGen.initialize(512);
        final KeyPair kPair = kPairGen.genKeyPair();

        final PrivateKey privateKey = kPair.getPrivate();
        final PublicKey publicKey = kPair.getPublic();

        System.out.println("private key: " + privateKey);
        System.out.println("public key: " + publicKey);

        Signature sign = Signature.getInstance("SHA1withDSA");
        Signature verify = Signature.getInstance("SHA1withDSA");
        sign.initSign(privateKey);
        verify.initVerify(publicKey);
        sign.update(byteMessage);
        verify.update(byteMessage);

        byte[] generatedSignature = sign.sign();
        boolean match = verify.verify(generatedSignature);

        System.out.println();
        System.out.println("match: " + match);
    }
}