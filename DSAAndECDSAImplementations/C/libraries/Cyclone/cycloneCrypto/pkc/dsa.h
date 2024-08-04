/**
 * @file dsa.h
 * @brief DSA (Digital Signature Algorithm)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.2
 **/

#ifndef _DSA_H
#define _DSA_H

//Dependencies
#include <Cyclone\cycloneCrypto\core\crypto.h> //"core/crypto.h"
#include <Cyclone\cycloneCrypto\mpi\mpi.h> //"mpi/mpi.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief DSA domain parameters
 **/

typedef struct
{
   Mpi p; ///<Prime modulus
   Mpi q; ///<Group order
   Mpi g; ///<Group generator
} DsaDomainParameters;


/**
 * @brief DSA public key
 **/

typedef struct
{
   DsaDomainParameters params; ///<DSA domain parameters
   Mpi y;                      ///<Public key value
} DsaPublicKey;


/**
 * @brief DSA private key
 **/

typedef struct
{
   DsaDomainParameters params; ///<DSA domain parameters
   Mpi x;                      ///<Secret exponent
   int_t slot;                 ///<Private key slot
} DsaPrivateKey;


// //struct added by Cocilova Marco
// typedef struct {
//     Mpi privateValue;  // private key value
//     Mpi publicValue;  // public key value
// } DsaKeyPair;


/**
 * @brief DSA signature
 **/

typedef struct
{
   Mpi r;
   Mpi s;
} DsaSignature;


//DSA related constants
extern const uint8_t DSA_OID[7];
extern const uint8_t DSA_WITH_SHA1_OID[7];
extern const uint8_t DSA_WITH_SHA224_OID[9];
extern const uint8_t DSA_WITH_SHA256_OID[9];
extern const uint8_t DSA_WITH_SHA384_OID[9];
extern const uint8_t DSA_WITH_SHA512_OID[9];
extern const uint8_t DSA_WITH_SHA3_224_OID[9];
extern const uint8_t DSA_WITH_SHA3_256_OID[9];
extern const uint8_t DSA_WITH_SHA3_384_OID[9];
extern const uint8_t DSA_WITH_SHA3_512_OID[9];

//DSA related functions
void dsaInitDomainParameters(DsaDomainParameters *params);
void dsaFreeDomainParameters(DsaDomainParameters *params);
//function added by Cocilova Marco
error_t dsaDomainParametersCopy(DsaDomainParameters *r, const DsaDomainParameters *params);
//function added by Cocilova Marco
bool_t dsaCheckDomainParameters(const DsaDomainParameters * params);

void dsaInitPublicKey(DsaPublicKey *key);
void dsaFreePublicKey(DsaPublicKey *key);
//function added by Cocilova Marco
error_t dsaGeneratePublicKey(DsaPublicKey *pub, const DsaPrivateKey *priv);

void dsaInitPrivateKey(DsaPrivateKey *key);
void dsaFreePrivateKey(DsaPrivateKey *key);

void dsaInitSignature(DsaSignature *signature);
void dsaFreeSignature(DsaSignature *signature);

//function added by Cocilova Marco
error_t dsaGenerateGValue(Mpi *g, const DsaDomainParameters *params, const Mpi *h);

error_t dsaWriteSignature(const DsaSignature *signature, uint8_t *data, size_t *length);
error_t dsaReadSignature(const uint8_t *data, size_t length, DsaSignature *signature);

error_t dsaGenerateSignature(const PrngAlgo *prngAlgo, void *prngContext,
   const DsaPrivateKey *key, const uint8_t *digest, size_t digestLen,
   DsaSignature *signature);

error_t dsaVerifySignature(const DsaPublicKey *key,
   const uint8_t *digest, size_t digestLen, const DsaSignature *signature);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
