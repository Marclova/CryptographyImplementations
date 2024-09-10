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

package DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.SecureRandomGenerator;

public class DSAParametersCalculator extends ParametersCalculator
{
    /**
     * Generates and sets the 'g' value used for digital signature and returns the new parameters spec.
     * The inserted parameter spec must have all the parameters but the initial value of 'g' will be ignored (so 'g' may be null).
     * 
     * @param dsaParams The parameters spec containing the necessary parameters.
     * @param srg The secure pseudo-random generator.
     * @return The calculated 'g' value as a BigInteger
     */
    @Override
    public DSAParameterSpec calculateGValueAndUpdateParameterSpec(AlgorithmParameterSpec params, SecureRandomGenerator srg)
    {
        if (!(params instanceof DSAParameterSpec))
        {
            throw new IllegalArgumentException("The method 'calculateGValue' requires a DSAParameterSpec, but received a "
                                                + params.getClass() + " instead.");
        }

        DSAParameterSpec dsaParams = (DSAParameterSpec) params;

        BigInteger field = dsaParams.getP();
        BigInteger q = dsaParams.getQ();
        BigInteger h = srg.generateBiasedRandomBigIntegerBetweenExclusive(new BigInteger("1"), field);
        
        // compute g = ( h^((p-1)/n) )
        BigInteger g = h.modPow(
                            field.subtract(BigInteger.ONE)
                            .multiply(q.modInverse(field)).mod(field),
                            field
                        );
        
        return new DSAParameterSpec(field, q, g);
    }

    @Override
    public DSAPrivateKeySpec calculatePrivateKeySpec(byte[] privateKeyValue, AlgorithmParameterSpec params)
    {
        if (!(params instanceof DSAParameterSpec))
        {
            throw new IllegalArgumentException("The method 'calculateGValue' requires a DSAParameterSpec, but received a "
                                                + params.getClass() + " instead.");
        }

        DSAParameterSpec dsaParams = (DSAParameterSpec) params;

        return new DSAPrivateKeySpec(new BigInteger(privateKeyValue), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
    }

    @Override
    public DSAPublicKeySpec calculatePublicKeySpec(byte[] privateKeyValue, AlgorithmParameterSpec params)
    {
        if (!(params instanceof DSAParameterSpec))
        {
            throw new IllegalArgumentException("The method 'calculateGValue' requires a DSAParameterSpec, but received a "
                                                + params.getClass() + " instead.");
        }

        DSAParameterSpec dsaParams = (DSAParameterSpec) params;

        BigInteger p = dsaParams.getP();
        BigInteger g = dsaParams.getG();
        BigInteger privKValue = new BigInteger(privateKeyValue);
        //compute g^d (mod p)
        BigInteger pubKValue = g.modPow(privKValue, p);

        return new DSAPublicKeySpec(pubKValue, p, dsaParams.getQ(), g);
    }
}