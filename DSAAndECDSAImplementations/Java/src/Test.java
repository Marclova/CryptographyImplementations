// package DSAAndECDSAImplementations.Java.src;

// import java.lang.reflect.Parameter;
// import java.math.BigInteger;
// import java.security.InvalidAlgorithmParameterException;
// import java.security.KeyFactory;
// import java.security.KeyPairGenerator;
// import java.security.NoSuchAlgorithmException;
// import java.security.PrivateKey;
// import java.security.spec.DSAPrivateKeySpec;
// import java.security.spec.ECFieldFp;
// import java.security.spec.ECGenParameterSpec;
// import java.security.spec.ECParameterSpec;
// import java.security.spec.ECPoint;
// import java.security.spec.ECPrivateKeySpec;
// import java.security.spec.EllipticCurve;

// import DSAAndECDSAImplementations.Java.libraries.minorUtilities.BytesConsolePrinter;
// import DSAAndECDSAImplementations.Java.libraries.minorUtilities.ECPointConsolePrinter;
// import DSAAndECDSAImplementations.Java.libraries.native_calculation.parameters.DSAParametersCalculator;
// import DSAAndECDSAImplementations.Java.libraries.native_calculation.parameters.ECParametersCalculator;
// import DSAAndECDSAImplementations.Java.libraries.native_calculation.parameters.ParametersCalculator;
// import DSAAndECDSAImplementations.Java.libraries.parameters_containers.ECParameterSpecExtractor;

// // import DSAAndECDSAImplementations.Java.libraries.minorUtilities.CustomConsolePrinter;

// public class Test {
//     public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
//     {
//         System.out.println();
//         ECPointConsolePrinter ecPrinter = new ECPointConsolePrinter();
//         BytesConsolePrinter bytePrinter = new BytesConsolePrinter();

//         BigInteger one = new BigInteger("1");

//         BigInteger pValue = new BigInteger("131822006398165307258698055648413838687537767524671193922764733867799989387302018959074876252007822537180273324347375075132156773521963609412383460404934049365190601904571108395361576354462976935366413513250177554222238270271204765747908939012743527162703702046780423745988560805648320815268994567009996144811");
//         BigInteger qValue = new BigInteger("859374346742477646223583445091564221150206800453");

//         System.out.println("p mod q = " + pValue.subtract(one).mod(qValue));
//     }
// }