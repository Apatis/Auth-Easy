<?php
/**
 * MIT License
 *
 * Copyright (c) 2018, Pentagonal
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

declare(strict_types=1);

namespace Apatis\Auth\Easy;

/**
 * Class CryptOpenSSL
 * @package Apatis\Auth\Easy
 */
class CryptOpenSSL
{
    const DEFAULT_METHOD = "AES-256-CBC";

    /**
     * Encrypt Open SSL
     *
     * @param string $data  data to encrypt
     * @param string $key   secret key
     * @param string $method openssl method @see openssl_get_cipher_methods();
     *
     * @return string encryption data base64_encode json data
     */
    public static function encrypt(
        string $data,
        string $key,
        string $method = null
    ) : string {
        $availableMethods = openssl_get_cipher_methods(true);
        if ($method === null) {
            $method = self::DEFAULT_METHOD;
        } elseif (!in_array($method, $availableMethods)) {
            if (in_array(strtolower($method), $availableMethods)) {
                $method = strtolower($method);
            } else {
                $method = self::DEFAULT_METHOD;
            }
        }

        // hash
        $length   = openssl_cipher_iv_length($method);
        $originIV = self::generateIV($length);
        $newIv    = self::generateIV($length);
        $key      = hash_hmac('sha256', $key, $key, true);
        $ivKey    = hash_hmac('sha256', $key . $newIv, $key, true);
        return base64_encode(
            json_encode([
                $method,
                base64_encode($newIv),
                openssl_encrypt($originIV, $method, $ivKey, 0, $newIv),
                openssl_encrypt(
                    $data,
                    $method,
                    $key,
                    0,
                    $originIV
                )
            ])
        );
    }

    /**
     * @param int $length
     *
     * @return string
     */
    protected static function generateIV(int $length) : string
    {
        $iv = '';
        if ($length > 0) {
            $maxIteration = 20;
            do {
                $iv = openssl_random_pseudo_bytes($length, $isStrong);
                $maxIteration--;
            } while (! $isStrong && $maxIteration > 0);
        }

        return $iv;
    }

    /**
     * Decrypt with Open SSL that encrypted @uses CryptOpenSSL::encrypt()
     *
     * @param string $data
     * @param string $key
     *
     * @return false|string string of returned data otherwise false if failure
     */
    public static function decrypt(
        string $data,
        string $key
    ) {
        if (trim($data) === '') {
            return false;
        }

        $data = json_decode(base64_decode($data), true);
        if (json_last_error() !== JSON_ERROR_NONE
            || !is_array($data)
            || count($data) !== 4
        ) {
            return false;
        }

        list($method, $ivEncryption, $encryptedIV, $output) = $data;
        unset($data);

        if (!is_string($method)
            || !is_string($output)
            || !is_string($ivEncryption)
            || !is_string($encryptedIV)
            || !in_array($method, openssl_get_cipher_methods(true))
        ) {
            return false;
        }

        $length = openssl_cipher_iv_length($method);
        $ivEncryption = base64_decode($ivEncryption);
        if ($length !== strlen($ivEncryption)) {
            return false;
        }

        $key    = hash_hmac('sha256', $key, $key, true);
        $ivKey    = hash_hmac('sha256', $key . $ivEncryption, $key, true);
        $decodedIv = openssl_decrypt($encryptedIV, $method, $ivKey, 0, $ivEncryption);
        if (!is_string($decodedIv) || strlen($decodedIv) !== $length) {
            return false;
        }

        return openssl_decrypt(
            $output,
            $method,
            $key,
            0,
            $decodedIv
        );
    }
}
