package DSAAndECDSAImplementations.Java.libraries.parameters_calculation;

import java.security.spec.AlgorithmParameterSpec;
import java.security.NoSuchAlgorithmException;

public abstract class ParametersCalculator<A extends AlgorithmParameterSpec> {

    // /**
    //  * Return an instance of a class supporting the specified algorithm.
    //  * 
    //  * @param algorithm The name of the algorithm to apply.
    //  * @param <A> The parameters spec used by the instanced specified class.
    //  * @return The casted instance of a sub-type of 'ParametersCalculator<A extends AlgorithmParameterSpec>'.
    //  * @throws NoSuchAlgorithmException 
    //  */
    // @SuppressWarnings("unchecked")
    // public static <A extends AlgorithmParameterSpec> ParametersCalculator<A> simpleGetInstance(String algorithm)
    //     throws NoSuchAlgorithmException
    // {
    //     switch (algorithm) {
    //         case "DSA":
    //             return (ParametersCalculator<A>) new DSAParametersCalculator();

    //         case "EC":
    //             return (ParametersCalculator<A>) new ECParametersCalculator();
        
    //         default:
    //             throw new NoSuchAlgorithmException("It has been defined no class in this package supporting the "+algorithm+" algorithm.");
    //     }
    // }
    
    /**
     * Generates and sets the 'g' value used for digital signature and returns the new parameters spec.
     * The inserted parameter spec must have all the parameters but the initial value of 'g' will be ignored (so 'g' may be null).
     * note: This method does't return the result because it's not always representable by a single value.
     * 
     * @param params The parameters spec containing the necessary parameters.
     * @param srg The secure pseudo-random generator.
     * @return A new parameter spec containing the calculated 'g' value
     */
    public abstract A calculateGValueAndUpdate(A params, SecureRandomGenerator srg);
}
