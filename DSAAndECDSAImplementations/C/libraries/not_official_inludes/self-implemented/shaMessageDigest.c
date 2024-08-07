/**
 * @file shaMessageDigest.c
 * @brief Agile implementation of SHA256 (reference library owned by Oryx Embedded)
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

#include <not_official_inludes\self-implemented\shaMessageDigest.h>

/**
 * @brief Creates a digest of the given data (does't alloc memory)
 * @param data The uint8_t array to digest
 * @param digest The digested uint8_t array
 */
error_t sha256DigestData(uint8_t *r, const uint8_t *data)
{
    if(sizeof(r) != SHA256_DIGEST_SIZE)
    {
        return ERROR_ILLEGAL_PARAMETER;
    }
    
    Sha256Context sha256;
    sha256Init(&sha256);
    sha256Update(&sha256, &data, sizeof(data));
    sha256Final(&sha256, r);
    return NO_ERROR;
}
