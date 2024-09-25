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

package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.calculation;

import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.util.SecureRandomNumberGenerator;

public abstract class ParametersCalculator
{
    /**
     * Instances a ParametersCalculator's sub-type.
     * 
     * @param algorithm The required algorithm's name
     * @return The instanced ParametersCalculator's sub-type.
     * @throws NoSuchAlgorithmException when an unsupported algorithm is required.
     */
    public static ParametersCalculator simpleGetInstance(String algorithm) throws NoSuchAlgorithmException
    {
        switch (algorithm) {
            case "DSA":
                return new DSAParametersCalculator();

            case "EC":
                return new ECParametersCalculator();
        
            default:
                throw new NoSuchAlgorithmException();
        }
    }

    /**
     * Generates and sets the 'g' value used for digital signature and returns the new parameters spec.
     * The inserted parameter spec must have all the parameters but the initial value of 'g' will be ignored (so 'g' may be null).
     * 
     * @param params The parameters spec containing the necessary parameters.
     * @param srg The secure pseudo-random generator.
     * @return The calculated 'g' value which type depends from the used implementation
     */
    public abstract AlgorithmParameterSpec calculateGValueAndUpdateParameterSpec(AlgorithmParameterSpec params, SecureRandomNumberGenerator srg);

    /**
     * Calculates the private key
     * 
     * @param privateKeyValue The private key associated with the public key to create
     * @param params The AlgorithmParameterSpec parameters used to calculate the public key
     * @return The private key which type depends from the used implementation
     */
    public abstract KeySpec calculatePrivateKeySpec(byte[] privateKeyValue, AlgorithmParameterSpec params);

    /**
     * Calculates the public key
     * 
     * @param privateKeyValue The private key associated with the public key to create
     * @param params The AlgorithmParameterSpec parameters used to calculate the public key
     * @return The public key which type depends from the used implementation
     */
    public abstract KeySpec calculatePublicKeySpec(byte[] privateKeyValue, AlgorithmParameterSpec params);
}
