/**
 * @file stm32mp2xx_crypto.c
 * @brief STM32MP2 hardware cryptographic accelerator
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

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hardware/stm32mp2xx/stm32mp2xx_crypto.h"
#include "hardware/stm32mp2xx/stm32mp2xx_crypto_trng.h"
#include "hardware/stm32mp2xx/stm32mp2xx_crypto_hash.h"
#include "hardware/stm32mp2xx/stm32mp2xx_crypto_cipher.h"
#include "hardware/stm32mp2xx/stm32mp2xx_crypto_pkc.h"
#include "debug.h"

//Global variables
OsMutex stm32mp2xxCryptoMutex;


/**
 * @brief Initialize hardware cryptographic accelerator
 * @return Error code
 **/

error_t stm32mp2xxCryptoInit(void)
{
   error_t error;

   //Initialize status code
   error = NO_ERROR;

   //Create a mutex to prevent simultaneous access to the hardware
   //cryptographic accelerator
   if(!osCreateMutex(&stm32mp2xxCryptoMutex))
   {
      //Failed to create mutex
      error = ERROR_OUT_OF_RESOURCES;
   }

#if (STM32MP2XX_CRYPTO_TRNG_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize TRNG module
      error = trngInit();
   }
#endif

#if (STM32MP2XX_CRYPTO_HASH_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize HASH module
      error = hashInit();
   }
#endif

#if (STM32MP2XX_CRYPTO_CIPHER_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize CRYP module
      error = crypInit();
   }
#endif

#if (STM32MP2XX_CRYPTO_PKC_SUPPORT == ENABLED)
   //Check status code
   if(!error)
   {
      //Initialize PKA module
      error = pkaInit();
   }
#endif

   //Return status code
   return error;
}
