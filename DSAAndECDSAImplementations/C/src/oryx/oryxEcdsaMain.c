#include <stdio.h>
#include <time.h>
#include <Cyclone\cycloneCrypto\ecc\ecdsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>

#define SEED_LENGTH 32  //seed length for sha256

//low sample values
#define FIELD_LIMIT 107
#define A_VARIABLE 7
#define B_VARIABLE 17
#define G_POINT_X_COORDINATE 20
#define MAX_ATTEMPTS_TO_GENERATE_SIGNATURE 5

int main()
{
    printf("\n");
    // data sample
    const uint8_t data[] = "hello world!";
    // Initialization of the native number generator
    srand(time(NULL));

    // Initializing the sha256 cipher and calculating the data digest
    Sha256Context sha256;
    sha256Init(&sha256);
    sha256Update(&sha256, &data, sizeof(data));
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256Final(&sha256, digest);

    // Initializing 'PrngAlgo' and 'YarrowContext' as components for a simple pseudo-random number generator
    const PrngAlgo *prngAlgo = &yarrowPrngAlgo;

    YarrowContext yContext;
    yarrowInit(&yContext);
    uint8_t seed[SEED_LENGTH];
    for (size_t i = 0; i < sizeof(seed); i++) // this seed generation method is not secure
    {
        seed[i] = (rand()) % 255;
    }
    yarrowSeed(&yContext, seed, sizeof(seed));

    //initialize parameters
    EcDomainParameters params;
    ecInitDomainParameters(&params);
    mpiSetValue(&params.a, A_VARIABLE);
    mpiSetValue(&params.b, B_VARIABLE);
    mpiSetValue(&params.p, FIELD_LIMIT);
    mpiSetValue(&params.g.x, G_POINT_X_COORDINATE);
    ecGenerateCurvePoint(&params, &params.g.x, &params.g);
    ecCalculatePointOrder(&params,&params.g, &params.q);
    printf("Given public curve function variable 'a': %d\n", params.a.data[0]);
    printf("Given public curve function variable 'b': %d\n", params.b.data[0]);
    printf("Given public prime field limit 'p': %d\n", params.p.data[0]);
    printf("Given public 'x coordinate' of the generator point 'G': %d\n", params.g.x.data[0]);
    printf("Calculated public 'y coordinate' of the generator point 'G': %d\n", params.g.y.data[0]);
    printf("Calculated public generator point 'G' order and used as module 'q': %d\n", params.q.data[0]);

    printf("\n");

    //generate key pairs
    EcPrivateKey privK;
    ecInitPrivateKey(&privK);
    EcPublicKey pubK;
    ecInitPublicKey(&pubK);
    ecGenerateKeyPair(prngAlgo, &yContext, &params, &privK, &pubK);
    printf("Extracted private key 'd': %d\n", privK.d.data[0]);
    printf("Generated public key 'Q' (x,y): ( %d , %d )\n", pubK.q.x.data[0], pubK.q.y.data[0]);

    printf("\n");

    //generate signature
    EcdsaSignature sign;
    ecdsaInitSignature(&sign);
    error_t error; // necessary to loop attempts
    uint8_t i = 0; // necessary to break eventual infinite loop
    //sometimes the extracted 'k' value is unfit, so it is necessary to retry.
    while (error != NO_ERROR || i >= MAX_ATTEMPTS_TO_GENERATE_SIGNATURE)
    {
        error = ecdsaGenerateSignature(prngAlgo, &yContext, &params, &privK, digest, sizeof(digest), &sign);
        i++;
    }
    printf("Generated signature (r,s): ( %d , %d )\n", sign.r.data[0], sign.s.data[0]);
    printf("signature generated after '%u' attempts\n", i);

    printf("\n");

    //Converting the signature into a more agile format (such as an uint8_t array)
    uint8_t buffer[sizeof(&params.q.data)];
    size_t bufferSize = sizeof(buffer);
    ecdsaWriteSignature(&sign, buffer, &bufferSize);
    printf("Sent signature value (hex): ");
    for (size_t i = 0; i < sizeof(buffer); i++)
    {
        printf("%x ", buffer[i]);
    }
    printf("\n\n");

    ecFreePrivateKey(&privK);
    ecdsaFreeSignature(&sign);

    printf("- simulating the sending of the buffered signature, the parameters, the data and public key to the other person -\n\n");

    //reconverting the signature into a 'DsaSignature'
    EcdsaSignature receivedSignature;
    ecdsaInitSignature(&receivedSignature);
    ecdsaReadSignature(buffer, bufferSize, &receivedSignature);
    printf("checking signature...\n");
    // Verifying the generated signature (avoiding to hash the data yet again in this demonstration)
    error = ecdsaVerifySignature(&params, &pubK, digest, sizeof(digest), &receivedSignature);
    if(error == NO_ERROR)
    {
        printf("Signature verified!");
    }
    else
    {
        printf("Signature not recognised...\n");
        printf("error code: %d", error);
    }

    ecFreeDomainParameters(&params);
    ecFreePublicKey(&pubK);
    ecdsaFreeSignature(&receivedSignature);

    return (error == NO_ERROR) ? 1 : -1;
}