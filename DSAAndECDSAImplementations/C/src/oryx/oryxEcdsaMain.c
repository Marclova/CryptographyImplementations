#include <stdio.h>
#include <time.h>
#include <Cyclone\cycloneCrypto\ecc\ecdsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>

#define SEED_LENGTH 32  //seed length for sha256

#define FIELD_LIMIT 107
#define A_VARIABLE 7
#define B_VARIABLE 17
#define G_POINT_X_COORDINATE 47

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

    EcDomainParameters params;
    ecInitDomainParameters(&params);

    
}