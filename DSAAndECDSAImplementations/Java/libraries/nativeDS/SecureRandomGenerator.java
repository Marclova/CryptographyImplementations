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

package DSAAndECDSAImplementations.Java.libraries.native_calculation;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomGenerator {

    SecureRandom secureRandom;

    public SecureRandomGenerator() throws NoSuchAlgorithmException
    {
        this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
    }

    public SecureRandomGenerator(SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;
    }
    
    /**
     * Generates random number in the defined interval (borders excluded) using this object's instance of SecureRandom.
     * The generation is biased if the used SecureRandom's max value
     * is not a multiple (or a divisor) of (higherValue-lowerValue)
     * 
     * @param lowerValue The interval's lower value
     * @param higherValue The interval's higher value
     * @param valuesByteLength The length in bytes of the pseudo-random generated value.
     * @return A most probably biased pseudo-random BigInteger.
     */
    public BigInteger generateBiasedRandomBigIntegerBetweenExclusive(BigInteger lowerValue, BigInteger higherValue)
    {
        if (lowerValue.compareTo(new BigInteger("0")) != 1 || lowerValue.compareTo(higherValue) != -1)  //0 < lowerValue < higherValue
        {
            throw new IllegalArgumentException("lowerValue must be lower than higherValue");
        }
        short valuesByteLength = (short) Math.ceil((float)higherValue.bitCount() / 8);  //byteCount = (bitCount / 8) rounded up
        byte randomBytes[] = this.generatePositiveSecureRandomBytes(valuesByteLength);

        BigInteger randomValue = new BigInteger(randomBytes);  //convert bytes into a BigInteger value

          //This extraction method causes lower numbers to be more probable
         //if randomValue's max value is not a multiple of deltaInterval
        //(because the modulus operation is not uniform)
        BigInteger deltaInterval = higherValue.subtract(lowerValue);
        // Adjust randomValue to ensure it is within the desired range, excluding the bounds
        randomValue = randomValue
                        .mod(deltaInterval.subtract(new BigInteger("1")))   //Generates a number between 0 and deltaInterval-2
                        .add(lowerValue.add(new BigInteger("1")));          //Shifts the number to be between lowerValue+1 and higherValue-1
        return randomValue;
    }

    /**
     * Generates random number in the defined interval (borders excluded) using this object's instance of SecureRandom.
     * The generation is biased if the used SecureRandom's max value is not a multiple (or a divisor)
     * of the difference between the higher value and the lower value in range.
     * 
     * @param lowerValueByteLength The minimum byte length of the random value.
     * @param higherValueByteLength The maximum byte length of the random value.
     * @return The most probably biased random value.
     */
    public BigInteger generateBiasedRandomBigIntegerBetweenByteLengths(short lowerValueByteLength, short higherValueByteLength)
    {
        byte lowerByteValue[] = new byte[lowerValueByteLength];
        byte higherByteValue[] = new byte[higherValueByteLength];

        lowerByteValue[0] |= 0x1; //set the lowest positive number representable with its byte length
        
        for (int i = higherValueByteLength-1; i > 0; i--) //set the higher possible value...
        {
            higherByteValue[i] |= 0xFF;
        }
        higherByteValue[0] |= 0x7F; //...not modifying the sign bit
        
        return generateBiasedRandomBigIntegerBetweenExclusive(new BigInteger(lowerByteValue), new BigInteger(higherByteValue));
    }

    /**
     * Generates a random positive value using this object's instance of SecureRandom.
     * 
     * @param higherByteValue The maximum byte length of the random value.
     * @return A random number between 1 and 2^(higherByteValue-1)-1
     */
    public BigInteger generatePositiveRandomBigInteger(short higherByteValue)
    {
        return new BigInteger(this.generatePositiveSecureRandomBytes(higherByteValue));
    }

    /**
     * Generates an arbitrary long sequence of pseudo-causal bytes using this object's instance of SecureRandom.
     * The first bit is always '0'.
     * 
     * @param byteCount The number of bytes in the sequence to generate.
     * @return The pseudo-random byte array.
     */
    public byte[] generatePositiveSecureRandomBytes(short byteCount)
    {
        byte randomBytes[] = new byte[byteCount];
        this.secureRandom.nextBytes(randomBytes);  //generate random bytes
        randomBytes[0] &= 0x7F; // set the first bit to '0' with an 'AND' operation using the sequence '01111111'

        return randomBytes;
    }
}
