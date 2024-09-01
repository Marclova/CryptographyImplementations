package DSAAndECDSAImplementations.Java.libraries.parameters_calculation;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
