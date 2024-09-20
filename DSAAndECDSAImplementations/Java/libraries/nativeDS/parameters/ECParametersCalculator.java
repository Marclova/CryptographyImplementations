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
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import DSAAndECDSAImplementations.Java.libraries.NativeDS.util.SecureRandomNumberGenerator;
//optional import
import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;

/**
 * This class doesn't work due two few not-implemented methods
 */
public class ECParametersCalculator extends ParametersCalculator
{

    /**
     * Generates and sets the 'g' value used for digital signature and returns the new parameters spec.
     * The inserted parameter spec must have all the parameters and the 'G' point must have at least the 'x' coordinate set.
     * 
     * @param params The parameters spec containing the necessary parameters.
     * @param srg Is not used.
     * @return The calculated 'G' as an ECPoint
     */
    @Override
    public ECParameterSpec calculateGValueAndUpdateParameterSpec(AlgorithmParameterSpec params, SecureRandomNumberGenerator srg)
    {
        // if (!(params instanceof ECParameterSpec))
        // {
        //     throw new IllegalArgumentException("The method 'calculatePublicKey' requires a ECParameterSpec, but received a "
        //                                         + params.getClass() + " instead.");
        // }
        
        // ECParameterSpec ecParams = (ECParameterSpec) params;

        // ECPoint g = ecFieldFpCalculateGValue(ecParams);

        // return new ECParameterSpec(ecParams.getCurve(), g, ecParams.getOrder(), 1);
        throw new UnsupportedOperationException();
    }

    @SuppressWarnings("unused")
    private ECPoint ecFieldFpCalculateGValue(ECParameterSpec ecParams)
    {
        ParametersExtractor extractor = new ParametersExtractor();
        extractor.extractFromParameterSpec(ecParams);
        BigInteger xCoordinate = ((ECPoint) extractor.getG()).getAffineX();
        BigInteger a = extractor.getA();
        BigInteger b = extractor.getB();
        BigInteger field = extractor.getP();

        //Calculating Gy
        // y^2 = x^3 + ax + b => y = sqrt(x^3 + ax + b) (mod p)
        //compute Y^2 = x^3 + ax + b
        BigInteger yCoordinateSquare = xCoordinate.modPow(new BigInteger("3"), field)
                                    .add(
                                        a.multiply(xCoordinate).mod(field)
                                    ).add(b).mod(field);
        BigInteger yCoordinate = yCoordinateSquare.sqrt();
        
        //verification of the square root
        if (yCoordinate.pow(2).compareTo(yCoordinateSquare) != 0) //if y^2 != ySquare
        {
            BytesConsolePrinter printer = new BytesConsolePrinter();
            throw new IllegalArgumentException("The given 'x' coordinate (" + printer.byteArrayToString(xCoordinate.toByteArray()) +
                                                ") doesn't generate a valid 'y' in the curve");
        }

        return new ECPoint(xCoordinate, yCoordinate);
    }    

    public BigInteger calculatePointOrder(ECPoint point, ECParameterSpec ecParams)
    {
        ECPoint rPoint = this.ecFieldFpPointDouble(point, ecParams);

        if (rPoint.equals(point))  // (point + point = point) => point is already a point to infinity
        {
            return BigInteger.ONE;
        }

        ParametersExtractor extractor = new ParametersExtractor();
        extractor.extractFromParameterSpec(ecParams);
        BigInteger field = extractor.getP();
        BigInteger order = new BigInteger("2");

        while (!(rPoint.equals(point)))  // continue until (rPoint + point = point)
        {
            if (order.compareTo(field) == 0)
            {
                throw new IllegalArgumentException("The point (" + point.getAffineX() + ", " + point.getAffineY() + ") has no valid order.");
            }
            rPoint = this.ecFieldFpPointSum(rPoint, point, ecParams);
            order = order.add(BigInteger.ONE);
        }

        return order.subtract(BigInteger.ONE);
        // throw new UnsupportedOperationException("Method 'calculateGValueAndUpdateParamSpec' is unimplemented because projective coordinates are mind-boggling!");
    }

    public ECPrivateKeySpec calculatePrivateKeySpec(byte[] privateKeyValue, AlgorithmParameterSpec params)
    {
        if (!(params instanceof ECParameterSpec))
        {
            throw new IllegalArgumentException("The method 'calculatePublicKey' requires a ECParameterSpec, but received a "
                                                + params.getClass() + " instead.");
        }
        
        ECParameterSpec ecParams = (ECParameterSpec) params;

        return new ECPrivateKeySpec(new BigInteger(privateKeyValue), ecParams);
    }

    /**
     * Calculates the public key
     * 
     * @param privateKey The private key associated with the public key to create
     * @param ecParams The ECParameterSpec parameters used to calculate the public key
     * @return The public key as an ECPoint
     */
    @Override
    public ECPublicKeySpec calculatePublicKeySpec(byte[] privateKeyValue, AlgorithmParameterSpec params)
    {
        if (!(params instanceof ECParameterSpec))
        {
            throw new IllegalArgumentException("The method 'calculatePublicKey' requires a ECParameterSpec, but received a "
                                                + params.getClass() + " instead.");
        }
        
        ECParameterSpec ecParams = (ECParameterSpec) params;

        return  this.ecFieldFpCalculatePublicKey(privateKeyValue, ecParams);
    }

    /**
     * Calculates the public key in a EcFieldFp elliptic curve.
     * 
     * @param privateKeyValue The private key associated with the public key to create
     * @param ecParams The ECParameterSpec parameters used to calculate the public key
     * @return The public key as an ECPoint
     */
    private ECPublicKeySpec ecFieldFpCalculatePublicKey(byte[] privateKeyValue, ECParameterSpec ecParams)
    {
        BigInteger privKValue = new BigInteger(privateKeyValue);

        if (privKValue.compareTo(new BigInteger("2")) == -1)
        {
            throw new IllegalArgumentException("private key can't be less or equal one");
        }

        ECPoint gPoint = ecParams.getGenerator();

        ECPoint pubK = this.ecFieldFpPointDouble(gPoint, ecParams);
        privKValue = privKValue.subtract(new BigInteger("2"));  //with the double of the point two iterations has been spent
        
        while (privKValue.compareTo(BigInteger.ZERO) != 0) {
            pubK = this.ecFieldFpPointSum(pubK, gPoint, ecParams);
            privKValue.subtract(BigInteger.ONE);
        }

        return new ECPublicKeySpec(pubK, ecParams);
    }
    
    /**
     * Calculates the double of the given point.
     * 
     * @param pointToDouble The point to double
     * @param ecParams The ECParameterSpec parameters used to calculate the result
     * @return The ECPoint resulting from the operation "2P = R"
     */
    public ECPoint ecFieldFpPointDouble(ECPoint pointToDouble, ECParameterSpec ecParams)
    {
        // BigInteger xP = pointToDouble.getAffineX();
        // BigInteger yP = pointToDouble.getAffineY();
        // ECParameterSpecExtractor pProv = new ECParameterSpecExtractor(ecParams);
        // BigInteger a = pProv.getA();
        // BigInteger field = pProv.getP();
        // BigInteger two = new BigInteger("2");
        
        // //compute s = ( 3*xP^2 + a ) / (2*yP) (mod p)
        // BigInteger s = xP.modPow(two, field)
        //                 .multiply(new BigInteger("3")).mod(field)
        //                 .add(a).mod(field)
        //                 .multiply(  //multiply with the multiplicative inverse
        //                     yP.multiply(two).modInverse(field)
        //                 ).mod(field);
        // //compute xR = s^2 – 2*xP (mod p)
        // BigInteger xR = s.modPow(two, field)
        //                 .subtract(
        //                     xP.multiply(two).mod(field)
        //                 ).mod(field);
        // //compute yR = s * (xP - xR) - yP (mod p)
        // BigInteger yR = xP.subtract(xR).mod(field)
        //                 .multiply(s).mod(field)
        //                 .subtract(yP).mod(field);

        // return new ECPoint(xR, yR);
        throw new UnsupportedOperationException();
    }

    /**
     * Calculates the sum between the given points.
     * 
     * @param pPoint The first point to sum
     * @param qPoint The second point to sum
     * @param ecParams The ECParameterSpec parameters used to calculate the result
     * @return The ECPoint resulting from the operation "P + Q = R"
     */
    public ECPoint ecFieldFpPointSum(ECPoint pPoint, ECPoint qPoint, ECParameterSpec ecParams)
    {
        // BigInteger xP = pPoint.getAffineX();
        // BigInteger yP = pPoint.getAffineY();
        // BigInteger xQ = qPoint.getAffineX();
        // BigInteger yQ = qPoint.getAffineY();
        // ECParameterSpecExtractor pProv = new ECParameterSpecExtractor(ecParams);
        // BigInteger field = pProv.getP();
        // BigInteger two = new BigInteger("2");

        // //compute s = (yQ - yP) / (xQ - xP) (mod p)
        // BigInteger s = yQ.subtract(yP).mod(field)
        //                 .multiply(  //multiply with the multiplicative inverse
        //                     xQ.subtract(xP).modInverse(field)
        //                 ).mod(field);
        // //compute xR = s^2 - xP - xQ (mod p)
        // BigInteger xR = s.modPow(two, field)
        //                 .subtract(xP).mod(field)
        //                 .subtract(xQ).mod(field);
        // //compute yR = s*(xP - xR) - yP (mod p)    
        // BigInteger yR = s.multiply(
        //                     xP.subtract(xR).mod(field)
        //                 ).mod(field)
        //                 .subtract(yP).mod(field);

        // return new ECPoint(xR, yR);
        throw new UnsupportedOperationException();
    }
}