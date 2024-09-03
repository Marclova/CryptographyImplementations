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
#include <Cyclone\cycloneCrypto\ecc\ecdsa.h>
#include <Cyclone\cycloneCrypto\rng\yarrow.h>
// #include <not_official_inludes\self-implemented\yarrowPRNG.h>
// #include <not_official_inludes\self-implemented\shaMessageDigest.h>

#define SEED_LENGTH 32  //seed length for sha256

//low sample values
// #define MAX_ATTEMPTS_TO_GENERATE_SIGNATURE 10

#define FIELD_LIMIT 131
#define A_VARIABLE 7
#define B_VARIABLE 17
#define G_POINT_X_COORDINATE 94

#define FILE_TO_SIGN "hello world!"

int main()
{
    printf("\n");

    //initialize the Pseudo-Random-Number-Generator
    YarrowContext yContext;
    yarrowInit(&yContext);
    yarrowSetSimpleTimePRSeed(&yContext);

    //initialize parameters
    EcDomainParameters params;
    ecInitDomainParameters(&params);
    mpiSetValue(&params.a, A_VARIABLE);
    mpiSetValue(&params.b, B_VARIABLE);
    mpiSetValue(&params.p, FIELD_LIMIT);
    mpiSetValue(&params.g.x, G_POINT_X_COORDINATE);
    ecGenerateCurvePoint(&params, &params.g.x, &params.g);
    ecCalculatePointOrder(&params, &params.g, &params.q);
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
    ecGenerateKeyPair(&yarrowPrngAlgo, &yContext, &params, &privK, &pubK);
    printf("Extracted private key 'd': %d\n", privK.d.data[0]);
    printf("Generated public key 'Q' (x,y): ( %d , %d )\n", pubK.q.x.data[0], pubK.q.y.data[0]);

    printf("\n");

    //generate signature
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256Compute(FILE_TO_SIGN, sizeof(digest), digest);
    EcdsaSignature sign;
    ecdsaInitSignature(&sign);
    error_t error; // necessary to loop attempts
    error = ecdsaGenerateSignature(&yarrowPrngAlgo, &yContext, &params, &privK, digest, sizeof(digest), &sign);
    
    printf("Generated signature (r,s): ( %d , %d )\n", sign.r.data[0], sign.s.data[0]);    
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