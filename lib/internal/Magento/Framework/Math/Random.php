<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Magento\Framework\Math;

use Zend\Math\Rand;

/**
 * Random data generator
 */
class Random
{
    /**#@+
     * Frequently used character classes
     */
    const CHARS_LOWERS = 'abcdefghijklmnopqrstuvwxyz';

    const CHARS_UPPERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    const CHARS_DIGITS = '0123456789';

    /**#@-*/

    /**
     * Get random string
     *
     * @param int         $length
     * @param null|string $chars
     * @return string
     */
    public function getRandomString($length, $chars = null)
    {
        if (null === $chars) {
            $chars = self::CHARS_LOWERS . self::CHARS_UPPERS . self::CHARS_DIGITS;
        }

        return Rand::getString($length, $chars);
    }

    /**
     * Return a random number in the specified range
     *
     * @param $min [optional]
     * @param $max [optional]
     * @return int A random integer value between min (or 0) and max
     */
    public static function getRandomNumber($min = 0, $max = null)
    {
        if (null === $max) {
            $max = PHP_INT_MAX;
        }

        return Rand::getInteger($min, $max);
    }

    /**
     * Generate a hash from unique ID
     *
     * @param string $prefix
     * @return string
     */
    public function getUniqueHash($prefix = '')
    {
        return $prefix . md5(uniqid(microtime() . self::getRandomNumber(), true));
    }
}
