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

#include <stdio.h>
#include <Cyclone\cycloneCrypto\pkc\dsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>
// #include <not_official_inludes\self-implemented\yarrowPRNG.h>
// #include <not_official_inludes\self-implemented\shaMessageDigest.h>

//low sample values
#define DSA_PRIME_VALUE 107
#define DSA_MODULE 53

#define PRIVATE_KEY_VALUE 34
#define FILE_TO_SIGN "hello world!"

int main()
{   
    printf("\n");

    //initialize the Pseudo-Random-Number-Generator
    YarrowContext yContext;
    yarrowInit(&yContext);
    yarrowSetSimpleTimePRSeed(&yContext);

    // Initialing the DSA variables 'p', 'q', and 'h'
    DsaDomainParameters params;
    dsaInitDomainParameters(&params);
    mpiSetValue(&params.p, DSA_PRIME_VALUE);
    mpiSetValue(&params.q, DSA_MODULE);

    Mpi h;
    mpiInit(&h);
    mpiRandRange(&h, &params.p, &yarrowPrngAlgo, &yContext);

    #pragma region sign application

    //calculating generator
    dsaGenerateGValue(&params.g, &params, &h);

    // Initializing the private key
    DsaPrivateKey privK;
    dsaInitPrivateKey(&privK);
    dsaDomainParametersCopy(&privK.params, &params);
    mpiSetValue(&privK.x, PRIVATE_KEY_VALUE);

    // Generating the public key
    DsaPublicKey pubK;
    dsaInitPublicKey(&pubK);
    dsaGeneratePublicKey(&pubK, &privK);

    // Signing the given data
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256Compute(FILE_TO_SIGN, sizeof(digest), digest);
    DsaSignature sign;
    dsaInitSignature(&sign);
    dsaGenerateSignature(&yarrowPrngAlgo, &yContext, &privK, digest, sizeof(digest), &sign);

    //Converting the signature into a format fit to be sent (such as an uint8_t array)
    uint8_t buffer[sizeof(&params.q.data)];
    size_t bufferSize = sizeof(buffer);
    dsaWriteSignature(&sign, buffer, &bufferSize);  //can't use 'sizeof(buffer)' here because a pointer is required


    //reconverting the signature into a 'DsaSignature'
    DsaSignature receivedSignature;
    dsaInitSignature(&receivedSignature);
    dsaReadSignature(buffer, sizeof(buffer), &receivedSignature);

    printf("checking signature...\n");
    // Verifying the generated signature (avoiding to hash the data yet again in this demonstration)
    error_t error = dsaVerifySignature(&pubK, digest, sizeof(digest), &receivedSignature);
    
    #pragma endregion

    #pragma region print commands

    printf("Given public prime value 'p': %d\n", params.p.data[0]);
    printf("Given public module 'q': %d\n", params.q.data[0]);
    printf("\nExtracted secret parameter 'h': %d\n", h.data[0]);
    printf("Generated public generator value 'g': %u\n", params.g.data[0]);
    printf("\n");

    printf("Generated signature (r,s): (%u , %u)", sign.r.data[0], sign.s.data[0]);
    printf("\n");

    printf("Given private key 'x': %d\n", privK.x.data[0]);
    printf("Generated public key 'y': %d\n", pubK.y.data[0]);
    printf("\n");

    printf("- simulating the sending of the buffered signature, the data and public key to the other person -\n\n");

    printf("Sent signature value (hex): ");
    for (size_t i = 0; i < sizeof(buffer); i++)
    {
        printf("%x ", buffer[i]);
    }
    printf("\n\n");

    if(error == NO_ERROR)
    {
        printf("Signature verified!");
    }
    else
    {
        printf("Signature not recognised...\n");
        printf("error code: %d", error);
    }

    #pragma endregion

    mpiFree(&h);
    dsaFreeDomainParameters(&params);
    dsaFreePrivateKey(&privK);
    dsaFreeSignature(&sign);
    dsaFreeSignature(&receivedSignature);
    dsaFreePublicKey(&pubK);
    yarrowDeinit(&yContext);
    
    return (error == NO_ERROR) ? 1 : -1;
}