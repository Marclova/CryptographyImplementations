package DSAAndECDSAImplementations.Java.src;

import java.math.BigInteger;

public class Test {
    public static void main(String[] args) {
        System.out.println();
        
        BigInteger pMinus1 = new BigInteger("131822006398165307258698055648413838687537767524671193922764733867799989387302018959074876252007822537180273324347375075132156773521963609412383460404934049365190601904571108395361576354462976935366413513250177554222238270271204765747908939012743527162703702046780423745988560805648320815268994567009996144810");
        BigInteger q = new BigInteger("859374346742477646223583445091564221150206800453");

        BigInteger divisionProduct = pMinus1.divide(q);
        System.out.println("divisionProduct: " + divisionProduct);

        boolean doubleCheck = divisionProduct.multiply(q).compareTo(pMinus1) == 0;

        System.out.println("doubleCheck: "+doubleCheck);
    }
}