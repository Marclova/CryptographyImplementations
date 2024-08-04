#include <stdio.h>
#include <time.h>
#include <Cyclone\cycloneCrypto\pkc\dsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>

#define SEED_LENGTH 32 //seed length for sha256

//low sample values
#define DSA_PRIME_VALUE 107
#define DSA_MODULE 53
#define DSA_PRIVATE_KEY_VALUE 34

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

    // Initialing the DSA variables 'p', 'q', 'h', and 'g'
    DsaDomainParameters params;
    dsaInitDomainParameters(&params);
    mpiSetValue(&params.p, DSA_PRIME_VALUE);
    mpiSetValue(&params.q, DSA_MODULE);
    printf("Given public parameter 'p' value: %d\n", params.p.data[0]);
    printf("Given public parameter 'q' value: %d\n", params.q.data[0]);

    Mpi h;
    mpiInit(&h);
    mpiSetValue(&h, ((rand() % (DSA_PRIME_VALUE-3)) + 2) );
    printf("\nExtracted secret parameter 'h' value: %d\n", h.data[0]);

    dsaGenerateGValue(&params.g, &params, &h);
    printf("Generated public parameter 'g' value: %u\n", params.g.data[0]);

    if(!dsaCheckDomainParameters(&params)) //TODO remove this check
    {
        printf("ERROR: Wrong parameters");
        return -1;
    }

    printf("\n");

    // Initializing the private key
    DsaPrivateKey privK;
    dsaInitPrivateKey(&privK);
    dsaDomainParametersCopy(&privK.params, &params);
    mpiSetValue(&privK.x, DSA_PRIVATE_KEY_VALUE);
    printf("Given private key 'x' value: %d\n", privK.x.data[0]);

    // Generating the public key
    DsaPublicKey pubK;
    dsaInitPublicKey(&pubK);
    dsaGeneratePublicKey(&pubK, &privK);
    printf("Generated public key 'y' value: %d\n", pubK.y.data[0]);

    printf("\n");

    // Signing the given data
    DsaSignature sign;
    dsaInitSignature(&sign);
    dsaGenerateSignature(prngAlgo, &yContext, &privK, digest, sizeof(digest), &sign);
    printf("Generated signature (r,s): (%u , %u)", sign.r.data[0], sign.s.data[0]);

    printf("\n");

    //Converting the signature into a more agile format (such as an uint8_t array)
    uint8_t buffer[sizeof(&params.q.data)];
    size_t bufferSize = sizeof(buffer);
    dsaWriteSignature(&sign, buffer, &bufferSize);
    printf("Sent signature value (hex): ");
    for (size_t i = 0; i < sizeof(buffer); i++)
    {
        printf("%x ", buffer[i]);
    }
    printf("\n\n");

    mpiFree(&h);
    dsaFreeDomainParameters(&params);
    dsaFreePrivateKey(&privK);
    dsaFreeSignature(&sign);


    /*--- sending buffered signature, the data and private key to the other person ---*/

    //reconverting the signature into a 'DsaSignature'
    DsaSignature receivedSignature;
    dsaInitSignature(&receivedSignature);
    dsaReadSignature(buffer, sizeof(buffer), &receivedSignature);

    printf("checking signature...\n");
    // Verifying the generated signature (avoiding to hash the data yet again in this demonstration)
    error_t error = dsaVerifySignature(&pubK, digest, sizeof(digest), &receivedSignature);
    if(error == NO_ERROR)
    {
        printf("Signature verified!");
    }
    else
    {
        printf("Signature not recognised...\n");
        printf("%d", error);
    }
    

    dsaFreeSignature(&receivedSignature);
    dsaFreePublicKey(&pubK);
    
    return 1;
}