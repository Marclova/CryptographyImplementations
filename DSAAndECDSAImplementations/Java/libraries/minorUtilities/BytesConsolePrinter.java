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

package DSAAndECDSAImplementations.Java.libraries.minorUtilities;

public class BytesConsolePrinter
{
    public String byteArrayToString(byte[] bytes)
    {
        if (bytes.length > 8)
        {
            return this.byteArrayToStringAsHex(bytes);
        }
        
        return this.byteArrayToStringAsDecimal(bytes);
    }
    
    public String byteArrayToStringAsHex(byte[] bytes)
    {
        String result = new String();

        result += String.format("%02X", bytes[0] & 0xFF);

        for (int i = 1; i < bytes.length; i++)
        {
            result += " " + String.format("%02X", bytes[i] & 0xFF);
        }

        return result;
    }

    public String byteArrayToStringAsDecimal(byte[] bytes)
    {
        if (bytes.length > 8)
        {
            throw new IllegalArgumentException("Value too high");    
        }

        long value = 0;
        for (int i = 0; i < bytes.length; i++) {
            value <<= 8;
            value |= (bytes[i] & 0xFF);
        }

        return (""+value);
    }
}