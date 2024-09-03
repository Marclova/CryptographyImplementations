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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
// import java.security.spec.ECParameterSpec;



import DSAAndECDSAImplementations.Java.libraries.parameters_calculation.SecureRandomGenerator;
import DSAAndECDSAImplementations.Java.libraries.parameters_calculation.DSAParametersCalculator;

public class AllImplementationsMain {
    public static void main(String[] args)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {

        System.out.println();

        //Defining initial values
        byte[] FileToSign = "Hello World!".getBytes();
        SecureRandomGenerator srg = new SecureRandomGenerator();

        //Choose one of those algorithms
        String KeyPairGeneratorAlgorithmName = "EC";
        // String KeyPairGeneratorAlgorithmName = "DSA";
        
        String hashAlgorithmName;
        AlgorithmParameterSpec parameters;
        

        //settings for DSA
        if (KeyPairGeneratorAlgorithmName.equals("DSA"))
        {
            hashAlgorithmName = "SHA256withDSA";
            BigInteger pValue = new BigInteger("131822006398165307258698055648413838687537767524671193922764733867799989387302018959074876252007822537180273324347375075132156773521963609412383460404934049365190601904571108395361576354462976935366413513250177554222238270271204765747908939012743527162703702046780423745988560805648320815268994567009996144811");
            BigInteger qValue = new BigInteger("859374346742477646223583445091564221150206800453");
            parameters = new DSAParametersCalculator()
                            .calculateGValueAndUpdate(new DSAParameterSpec(pValue, qValue, null), srg);
        }
        //settings for ECDSA
        else if (KeyPairGeneratorAlgorithmName.equals("EC"))
        {
            hashAlgorithmName = "SHA256withECDSA";
            parameters = new ECGenParameterSpec("secp256r1");
            // parameters = new ECParametersCalculator().calculateGValueAndUpdate((ECParameterSpec)parameters, srg);
        }
        else
        {
            throw new NoSuchAlgorithmException("The selected algorithm "+KeyPairGeneratorAlgorithmName+" is not between the options");
        }

        System.out.println("signature algorithm choose: " + KeyPairGeneratorAlgorithmName);
        System.out.println("parameters:\n" + parameters);
        System.out.println();

        //extraction of the private key and generation of the public key
        KeyPairGenerator kPairGen = KeyPairGenerator.getInstance(KeyPairGeneratorAlgorithmName);
        kPairGen.initialize(parameters);
        final KeyPair kPair = kPairGen.genKeyPair();
        PrivateKey privK = kPair.getPrivate();
        PublicKey pubK = kPair.getPublic();

        System.out.println("extracted private key value:\n" + privK.getEncoded());
        System.out.println("extracted public key value:\n" + pubK.getEncoded());
        System.out.println();

        //application of the file signature
        Signature sign = Signature.getInstance(hashAlgorithmName);
        sign.initSign(privK);
        sign.update(FileToSign);
        byte[] generatedSignature = sign.sign();
        
        System.out.println("generated signature: "+generatedSignature);

        //verification of the file signature
        Signature verify = Signature.getInstance(hashAlgorithmName);
        verify.initVerify(pubK);
        verify.update(FileToSign);
        boolean match = verify.verify(generatedSignature);

        System.out.println();
        System.out.println("Signature match: " + match);
    }
}