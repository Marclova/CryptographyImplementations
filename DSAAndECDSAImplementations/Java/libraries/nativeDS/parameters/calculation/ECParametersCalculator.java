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

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import DSAAndECDSAImplementations.Java.libraries.notOfficialImports.ashu_tosh_kumar.TonelliShanks;
import DSAAndECDSAImplementations.Java.libraries.NativeDS.parameters.extraction.ECParametersExtractor;
import DSAAndECDSAImplementations.Java.libraries.NativeDS.util.SecureRandomNumberGenerator;

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
        if (!(params instanceof ECParameterSpec))
        {
            throw new IllegalArgumentException("The method 'calculatePublicKey' requires a ECParameterSpec, but received a "
                                                + params.getClass() + " instead.");
        }
        
        ECParameterSpec ecParams = (ECParameterSpec) params;

        ECPoint g = this.ecFieldFpCalculateGValue(ecParams);
        return new ECParameterSpec(ecParams.getCurve(), g, ecParams.getOrder(), 1);

        // BigInteger gOrder = this.calculatePointOrder(g, ecParams);
        // return new ECParameterSpec(ecParams.getCurve(), g, gOrder, 1);
    }

    public ECPoint ecFieldFpCalculateGValue(ECParameterSpec ecParams)
    {
        ECParametersExtractor extractor = new ECParametersExtractor();
        extractor.extractFromECFieldFpParameterSpec(ecParams);

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
                                    ).mod(field)
                                    .add(b).mod(field);

        BigInteger yCoordinate = TonelliShanks.tonelliShanks(yCoordinateSquare, field);

        return new ECPoint(xCoordinate, yCoordinate);
    }

    public BigInteger calculatePointOrder(ECPoint point, ECParameterSpec ecParams)
    {
        // ECPoint rPoint = this.ecFieldFpPointDouble(point, ecParams);

        // if (rPoint.equals(point))  // (point + point = point) => point is already a point to infinity
        // {
        //     return BigInteger.ONE;
        // }

        // ECParametersExtractor extractor = new ECParametersExtractor();
        // extractor.extractFromParameterSpec(ecParams);
        // BigInteger field = extractor.getP();
        // BigInteger order = new BigInteger("2");

        // while (!(rPoint.equals(point)))  // continue until (rPoint + point = point)
        // {
        //     if (order.compareTo(field) == 0)
        //     {
        //         throw new IllegalArgumentException("The point (" + point.getAffineX() + ", " + point.getAffineY() + ") has no valid order.");
        //     }
        //     rPoint = this.ecFieldFpPointSum(rPoint, point, ecParams);
        //     order = order.add(BigInteger.ONE);
        // }

        // return order.subtract(BigInteger.ONE);
        // // throw new UnsupportedOperationException("Method 'calculateGValueAndUpdateParamSpec' is unimplemented because projective coordinates are mind-boggling!");
        // ECProjectivePoint actualProjectivePoint = new ECProjectivePoint(point);
        // BigInteger order = BigInteger.ONE;
 
        // if (actualProjectivePoint.isPointToInfinity())
        // {
        //     return order;
        // }

        // ECParametersExtractor ecExtractor = new ECParametersExtractor();
        // ecExtractor.extractFromECFieldFpParameterSpec(ecParams);
        // BigInteger field = ecExtractor.getP();
        // ECProjectivePoint previousProjectivePoint = actualProjectivePoint.clone();

        // while (!(actualProjectivePoint.isPointToInfinity()))
        // {
        //     actualProjectivePoint = this.ecFieldFpPointSum(actualProjectivePoint, previousProjectivePoint, ecParams);
        //     order = order.add(BigInteger.ONE);
            
        //     if (order.compareTo(field) == 0)
        //     {
        //         throw new ArithmeticException("The order can't be equal or higher than the field.");
        //     }
        // }

        throw new UnsupportedOperationException("Didn't found an optimization to calculate it in a reasonable time.");
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

        if (privKValue.compareTo(BigInteger.TWO) == -1)
        {
            throw new IllegalArgumentException("private key can't be less or equal one");
        }

        ECProjectivePoint gPoint = new ECProjectivePoint(ecParams.getGenerator());

        ECProjectivePoint pubK = doubleAndADDPointSum(gPoint, privKValue, ecParams);

        return new ECPublicKeySpec(pubK, ecParams);
    }
    
    /**
     * Calculates the double of the given point.
     * 
     * @param pointToDouble The point to double
     * @param ecParams The ECParameterSpec parameters used to calculate the result
     * @return The ECPoint resulting from the operation "2P = R"
     */
    public ECProjectivePoint ecFieldFpPointDouble(ECProjectivePoint pointToDouble, ECParameterSpec ecParams)
    {
        if (pointToDouble.isPointToInfinity())
        {
            return pointToDouble;
        }

        ECParametersExtractor ecExtractor = new ECParametersExtractor();
        ecExtractor.extractFromECFieldFpParameterSpec(ecParams);

        BigInteger four = BigInteger.valueOf(4);
        BigInteger eight = BigInteger.valueOf(8);
        BigInteger a = ecExtractor.getA();
        BigInteger field = ecExtractor.getP();
        BigInteger xR = pointToDouble.getProjectiveX();
        BigInteger yR = pointToDouble.getProjectiveY();
        BigInteger zR = pointToDouble.getProjectiveZ();

        //compute A = zR^4 * a
        BigInteger aValue = zR.modPow(four, field);
        aValue = modIfNecessary(aValue.multiply(a), field);

        //compute B = xR^2
        BigInteger bValue = xR.modPow(BigInteger.TWO, field);

        //compute A = A + (3 * B)
        aValue = modIfNecessary(aValue.add(
                                    bValue.multiply(BigInteger.valueOf(3)))
                , field);
        
        //compute zR = zR * yR * 2
        zR = modIfNecessary(zR.multiply(yR), field);
        zR = modIfNecessary(zR.multiply(BigInteger.TWO), field);
        
        //compute yR = yR^2
        yR = yR.modPow(BigInteger.TWO, field);
        
        //compute B = xR * yR * 4
        bValue = modIfNecessary(xR.multiply(yR), field);
        bValue = modIfNecessary(bValue.multiply(four), field);

        //compute xR = A^2 - (2 * B)
        xR = modIfNecessary(aValue.pow(2)
                                .subtract(
                                    bValue.multiply(BigInteger.TWO)
                                )
            , field);

        //compute yR =  yR^2 * 8
        yR = modIfNecessary(yR.modPow(BigInteger.TWO, field)
                                .multiply(eight)
            , field);

        //compute B = (B - xR) * A
        bValue = modIfNecessary(bValue.subtract(xR), field);
        bValue = modIfNecessary(bValue.multiply(aValue), field);

        //compute yR = B - yR
        yR = modIfNecessary(bValue.subtract(yR), field);

        return new ECProjectivePoint(xR, yR, zR);
    }

    /**
     * Calculates the sum between the given points.
     * 
     * @param pPoint The first point to sum
     * @param qPoint The second point to sum
     * @param ecParams The ECParameterSpec parameters used to calculate the result
     * @return The ECPoint resulting from the operation "P + Q = R"
     */
    public ECProjectivePoint ecFieldFpPointSum(ECProjectivePoint pPoint, ECProjectivePoint qPoint, ECParameterSpec ecParams)
    {
        if (pPoint.isPointToInfinity())
        {
            return qPoint;
        }
        if (qPoint.isPointToInfinity())
        {
            return pPoint;
        }
        if (pPoint.equals(qPoint))
        {
            return this.ecFieldFpPointDouble(qPoint, ecParams);    
        }

        ECParametersExtractor ecExtractor = new ECParametersExtractor();
        ecExtractor.extractFromECFieldFpParameterSpec(ecParams);

        BigInteger field = ecExtractor.getP();
        BigInteger xR = pPoint.getProjectiveX();
        BigInteger yR = pPoint.getProjectiveY();
        BigInteger zR = pPoint.getProjectiveZ();
        BigInteger aValue = qPoint.getProjectiveX();
        BigInteger bValue = qPoint.getProjectiveY();
        BigInteger cValue = qPoint.getProjectiveZ();
        BigInteger vValue;

        //compute V = C^2
        vValue = cValue.modPow(BigInteger.TWO, field);
        
        //compute xR = xR * V
        xR = modIfNecessary(xR.multiply(vValue), field);
        
        //compute V = V * C
        vValue = modIfNecessary(vValue.multiply(cValue), field);
        
        //compute yR = yR * V
        yR = modIfNecessary(yR.multiply(vValue), field);
        
        //compute V = zR^2
        vValue = zR.modPow(BigInteger.TWO, field);
        
        //compute A = A * V
        aValue = modIfNecessary(aValue.multiply(vValue), field);
        
        //compute V = zR * V
        vValue = modIfNecessary(zR.multiply(vValue), field);
        
        //compute B = B * V
        bValue = modIfNecessary(bValue.multiply(vValue), field);
        
        //compute A = xR - A
        aValue = modIfNecessary(xR.subtract(aValue), field);
        
        //compute B = yR - B
        bValue = modIfNecessary(yR.subtract(bValue), field);

        // if (A == 0) {return pointToInfinity}
        if (aValue.compareTo(BigInteger.ZERO) == 0) 
        {
            return ECProjectivePoint.POINT_AT_INFINITY;
        }

        //compute xR = (XR * 2) - A
        xR = modIfNecessary(xR.multiply(BigInteger.TWO)
                            .subtract(aValue)
            , field);
        
        //compute yR = (yR * 2) - B
        yR = modIfNecessary(yR.multiply(BigInteger.TWO)
                            .subtract(bValue)
        , field);
        
        //compute zR = zR * C * A
        zR = modIfNecessary(zR.multiply(cValue), field);
        zR = modIfNecessary(zR.multiply(aValue), field);
        
        //compute V = A^2
        vValue = aValue.modPow(BigInteger.TWO, field);
        
        //compute A = A * V
        aValue = modIfNecessary(aValue.multiply(vValue), field);
        
        //compute V = V * xR
        vValue = modIfNecessary(vValue.multiply(xR), field);
        
        //compute xR = B^2
        xR = bValue.modPow(BigInteger.TWO, field);
        
        //compute xR = xR - V
        xR = modIfNecessary(xR.subtract(vValue), field);
        
        //compute V = V - (2 * xR)
        vValue = modIfNecessary(vValue.subtract(
                                    xR.multiply(BigInteger.TWO)
                                )
                , field);
        
        //compute B = B * V
        bValue = modIfNecessary(bValue.multiply(vValue), field);
        
        //compute A = A * yR
        aValue = modIfNecessary(aValue.multiply(yR), field);
        
        //compute yR = B - A
        yR = modIfNecessary(bValue.subtract(aValue), field);
        
        //compute yR = yR / 2
        yR = modIfNecessary(yR.multiply(BigInteger.TWO.modInverse(field)), field);

        return new ECProjectivePoint(xR, yR, zR);
    }

    private ECProjectivePoint doubleAndADDPointSum(ECProjectivePoint gPoint, BigInteger n, ECParameterSpec ecParams) {
        ECProjectivePoint result = ECProjectivePoint.POINT_AT_INFINITY;
        ECProjectivePoint addend = gPoint.clone();
    
        while (n.compareTo(BigInteger.ZERO) > 0)
        {
            if (n.testBit(0))
            {
                result = ecFieldFpPointSum(result, addend, ecParams);
            }
            addend = ecFieldFpPointDouble(addend, ecParams);
            n = n.shiftRight(1);
        }
    
        return gPoint;
    }

    private BigInteger modIfNecessary(BigInteger value, BigInteger field)
    {
        if (value.compareTo(field) >= 0)
        {
            return value.mod(field);
        }
        else
        {
            return value;
        }
    }
}