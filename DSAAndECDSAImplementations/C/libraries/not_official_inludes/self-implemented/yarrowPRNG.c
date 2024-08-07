/**
 * @file yarrowPRNG.c
 * @brief Agile implementation of Yarrow (reference library owned by Oryx Embedded)
 * 
 * @section license
 * 
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
 * 
 * @author Cocilova Marco
 **/

#include <time.h>
#include <not_official_inludes\self-implemented\yarrowPRNG.h>

void yarrowGenerateSha256PRSeed(YarrowContext *r)
{
    srand(time(NULL));
    yarrowInit(r);
    uint8_t seed[SHA256_SEED_LENGTH];
    for (size_t i = 0; i < sizeof(seed); i++) // this seed generation method is not secure
    {
        seed[i] = (rand()) % 255;
    }
    yarrowSeed(r, seed, sizeof(seed));
}