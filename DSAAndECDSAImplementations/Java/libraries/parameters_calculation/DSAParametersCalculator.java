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

package DSAAndECDSAImplementations.Java.libraries.parameters_calculation;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;

public class DSAParametersCalculator extends ParametersCalculator<DSAParameterSpec> {

    @Override
    public DSAParameterSpec calculateGValueAndUpdate(DSAParameterSpec params, SecureRandomGenerator srg)
    {
        BigInteger p = params.getP();
        BigInteger q = params.getQ();
        BigInteger h = srg.generateBiasedRandomBigIntegerBetweenExclusive(new BigInteger("1"), p);

        //compute g = h^((p-1)/n) (mod p)
        BigInteger g = h.modPow(
                                p.subtract(new BigInteger("1")).divide(q),  //exponent
                                p                                               //module
                               );
        return new DSAParameterSpec(p, q, g);
    }
}
