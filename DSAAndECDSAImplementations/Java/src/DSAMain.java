/*
 * MIT License
 * 
 * Copyright (c) 2024 Cocilova Marco
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package DSAAndECDSAImplementations.Java.src;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;
import DSAAndECDSAImplementations.Java.libraries.native_calculation.SecureRandomGenerator;
import DSAAndECDSAImplementations.Java.libraries.native_calculation.parameters.DSAParametersCalculator;

public class DSAMain {
    public static void main(String[] args)
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException
    {
        //Defining sample values
        byte[] FileToSign = "Hello World!".getBytes();
        BigInteger privateKeyValue = new BigInteger( "Custom private key value".getBytes() );
        BigInteger pValue = new BigInteger("131822006398165307258698055648413838687537767524671193922764733867799989387302018959074876252007822537180273324347375075132156773521963609412383460404934049365190601904571108395361576354462976935366413513250177554222238270271204765747908939012743527162703702046780423745988560805648320815268994567009996144811");
        BigInteger qValue = new BigInteger("859374346742477646223583445091564221150206800453");

        String KeyPairGeneratorAlgorithmName = "DSA";
        String hashAlgorithmName = "SHA256withDSA";

        //initializing utility classes
        SecureRandomGenerator srg = new SecureRandomGenerator();
        DSAParametersCalculator pCalculator = new DSAParametersCalculator();
        KeyFactory keyFactory = KeyFactory.getInstance(KeyPairGeneratorAlgorithmName);
        

        //parameters initialization
        BigInteger gValue = pCalculator.calculateGValue(new DSAParameterSpec(pValue, qValue, null), srg);
        
        DSAParameterSpec parameters = new DSAParameterSpec(pValue, qValue, gValue);

        DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(privateKeyValue, pValue, qValue, gValue);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        //calculating the public key
        DSAPublicKeySpec publicKeySpec = pCalculator.calculatePublicKey(privateKeySpec, parameters);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

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

        // - - - - - - - - - - - - - - - - - - - - - -

        BytesConsolePrinter cPrinter = new BytesConsolePrinter();
        
        System.out.println("\nselected 'p' module:\n" +
                            cPrinter.byteArrayToString(pValue.toByteArray()) + "\n");
        
        System.out.println("selected 'q' module:\n" +
        cPrinter.byteArrayToString(qValue.toByteArray()) + "\n");

        System.out.println("selected 'g' generator:\n" +
                            cPrinter.byteArrayToString(gValue.toByteArray()) + "\n");
        
        System.out.println("chosen private key value:\n" +
                            cPrinter.byteArrayToString(privateKey.getEncoded()) + "\n");

        System.out.println("calculated public key value:\n" +
                            cPrinter.byteArrayToString(publicKey.getEncoded()) + "\n");

        System.out.println("generated signature:\n" + 
                            cPrinter.byteArrayToString(generatedSignature) + "\n");

        System.out.println("Signature match: " + match);
    }
}