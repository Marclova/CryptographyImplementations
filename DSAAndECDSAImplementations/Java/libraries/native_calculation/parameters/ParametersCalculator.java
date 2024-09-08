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

package DSAAndECDSAImplementations.Java.libraries.native_calculation.parameters;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import DSAAndECDSAImplementations.Java.libraries.native_calculation.SecureRandomGenerator;

public abstract class ParametersCalculator {

    /**
     * Generates and sets the 'g' value used for digital signature and returns the new parameters spec.
     * The inserted parameter spec must have all the parameters but the initial value of 'g' will be ignored (so 'g' may be null).
     * 
     * @param params The parameters spec containing the necessary parameters.
     * @param srg The secure pseudo-random generator.
     * @return The calculated 'g' value which type depends from the used implementation
     */
    public abstract Object calculateGValue(AlgorithmParameterSpec params, SecureRandomGenerator srg);

    /**
     * Calculates the public key
     * 
     * @param privateKey The private key associated with the public key to create
     * @param params The AlgorithmParameterSpec parameters used to calculate the public key
     * @return The public key which type depends from the used implementation
     */
    public abstract KeySpec calculatePublicKey(KeySpec privateKey, AlgorithmParameterSpec params);

    // /**
    //  * 
    //  * 
    //  * @param params
    //  * @return
    //  */
    // public abstract ParameterSpecProvider extractValuesFromParameterSpec(AlgorithmParameterSpec params);
}
