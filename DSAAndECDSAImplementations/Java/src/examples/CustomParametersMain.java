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

package DSAAndECDSAImplementations.Java.src.examples;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;
import DSAAndECDSAImplementations.Java.libraries.minorUtilities.ECPointConsolePrinter;
import DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.extraction.*;
import DSAAndECDSAImplementations.Java.libraries.NativeDS.util.OperationsManager;

public class CustomParametersMain {
    public static void main(String[] args)
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException
    {
        //Defining sample values
        byte[] fileToSign = "Hello World!".getBytes();
        byte[] privateKeyValue = "Custom private key value".getBytes();
        BigInteger pValue = new BigInteger("131822006398165307258698055648413838687537767524671193922764733867799989387302018959074876252007822537180273324347375075132156773521963609412383460404934049365190601904571108395361576354462976935366413513250177554222238270271204765747908939012743527162703702046780423745988560805648320815268994567009996144811");
        BigInteger qValue = new BigInteger("859374346742477646223583445091564221150206800453");
        BigInteger a = new BigInteger("7");
        BigInteger b = new BigInteger("17");
        
        //generic parameters
        String KeyPairGeneratorAlgorithmName;
        String hashAlgorithmName;
        AlgorithmParameterSpec parameters;
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
                parameters = new DSAParameterSpec(pValue, qValue, null);
                extractor = new DSAParametersExtractor(); //just to print on console
                break;
            
            case 2: //This will throw an 'UnsupportedOperationException'
                KeyPairGeneratorAlgorithmName = "EC";
                hashAlgorithmName = "SHA256withECDSA";
                parameters = new ECParameterSpec(new EllipticCurve(new ECFieldFp(pValue), a, b),
                                                    new ECPoint(BigInteger.ONE, BigInteger.ZERO), qValue, 1);
                extractor = new ECParametersExtractor(); //just to print on console
                break;

            default:
                throw new IllegalArgumentException("invalid choice");
        }
        //#endregion

        //#region sign application
        
        //initializing parameters manager
        opManager = new OperationsManager(KeyPairGeneratorAlgorithmName, hashAlgorithmName);

        //custom parameters calculation
        parameters = opManager.calculateGValueAndUpdateParamSpec(parameters);

        KeyPair keyPair = opManager.calculateKeyPair(privateKeyValue, parameters);

        //applying the file signature
        byte[] generatedSignature = opManager.signFile(fileToSign, keyPair.getPrivate());

        //verifying the file signature
        boolean match = opManager.verifySignature(fileToSign, generatedSignature, keyPair.getPublic());

        //#endregion

        //#region print commands

        extractor.extractFromPublicKey(keyPair.getPublic());

        Object gValue = extractor.getG();
        Object yValue = extractor.getY();

        String gStringValue;
        String yStringValue;

        if (gValue instanceof BigInteger)
        {
            gStringValue = bytePrinter.byteArrayToString(((BigInteger) gValue).toByteArray());
            yStringValue = bytePrinter.byteArrayToString(((BigInteger) yValue).toByteArray());
        }
        else
        {
            gStringValue = ecPrinter.ecPointToString(((ECPoint) gValue));
            yStringValue = ecPrinter.ecPointToString(((ECPoint) yValue));
        }

        System.out.println("\nSelected algorithm: " + KeyPairGeneratorAlgorithmName + "\n");
        
        System.out.println("selected 'p' module:\n" +
                            bytePrinter.byteArrayToString(pValue.toByteArray()) + "\n");
        
        System.out.println("selected 'q' module:\n" +
        bytePrinter.byteArrayToString(qValue.toByteArray()) + "\n");

        System.out.println("calculated 'g' generator:\n" +
                            gStringValue + "\n");
        
        System.out.println("chosen private key value:\n" +
                            bytePrinter.byteArrayToString(privateKeyValue) + "\n");

        System.out.println("calculated public key value:\n" +
                            yStringValue + "\n");

        System.out.println("generated signature:\n" + 
                            bytePrinter.byteArrayToString(generatedSignature) + "\n");

        System.out.println("\n- simulating the sending of the buffered signature, the data and public key to the other person -\n");

        System.out.println("Signature match: " + match + "\n");

        //#endregion
    }
}