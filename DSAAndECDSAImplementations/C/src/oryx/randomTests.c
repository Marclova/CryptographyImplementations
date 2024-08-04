#include <stdio.h>
#include <Cyclone\cycloneCrypto\pkc\dsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>

#define SEED_LENGTH 32 // Length in bytes for SHA-256 seed

int main(int argc, char const *argv[])
{
    printf("\n");
    // error_t error = NO_ERROR;

    // const PrngAlgo *prngAlgo = &yarrowPrngAlgo;
    // YarrowContext yContext;
    // error += yarrowInit(&yContext);

    // uint8_t seedArray[SEED_LENGTH];
    // // memcpy(seedArray, &t, sizeof(t));
    
    // for (size_t i = 0; i < SEED_LENGTH; i++)
    // {
    //     seedArray[i] = (rand()) % 255;
    // }
    
    // // time_t seedChunk;
    // // for (size_t i = 0; i < SEED_LENGTH; i++)
    // // {
    // //     time(&seedChunk);
    // //     seedArray[i] = seedChunk;
    // // }
    
    // // error += yarrowSeed(&yContext, &seed)
    
    // // printf("seed: %d\n", seed);
    // // printf("value: %d\n", value);
    // // printf("seedChar: %d\n", seedArray[0]);
    // // printf("char: %c\n", seedArray[0]);

    // printf("seedArray: %.*s\n", SEED_LENGTH, seedArray);
    // // printf("t size: %u\n", sizeof(t));
    // // printf("t value: %u\n", t);
    // for (size_t i = 0; i < SEED_LENGTH; i++)
    // {
    //     printf("%c, ", seedArray[i]);
    // }
    

    // if(error == NO_ERROR)
    // {
    //     printf("\n Program terminated correctly");
    // }
    // else
    // {
    //     printf("\n Something went wrong during program execution");
    // }

    const uint32_t n = 10;

    for (size_t i = 0; i < 100; i++)
    {
        printf("%d, ", rand() % 10);
    }
    
}
