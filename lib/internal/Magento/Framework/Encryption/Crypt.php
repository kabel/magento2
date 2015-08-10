<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */

// @codingStandardsIgnoreFile

namespace Magento\Framework\Encryption;

use phpseclib\Crypt\Base;
use Zend\Math\Rand;

/**
 * Class encapsulates cryptographic algorithm
 */
class Crypt
{
    const MODE_CBC = 'cbc';

    const MODE_CFB = 'cfb';

    const MODE_CTR = 'ctr';

    const MODE_ECB = 'ecb';

    const MODE_OFB = 'ofb';

    const CIPHER_BLOWFISH = 'blowfish';

    const CIPHER_RIJNDAEL_128 = 'rijndael-128';

    const CIPHER_RIJNDAEL_256 = 'rijndael-256';

    /**
     * @var string
     */
    protected $_cipher;

    /**
     * @var string
     */
    protected $_mode;

    /**
     * @var string
     */
    protected $_initVector;

    /**
     * @var Base
     */
    protected $_adapter;

    /**
     * @var string
     */
    protected $_key;

    /**
     * @var array
     */
    protected $_blockLengthMap = [
        self::CIPHER_BLOWFISH => 64,
        self::CIPHER_RIJNDAEL_128 => 128,
        self::CIPHER_RIJNDAEL_256 => 256,
    ];

    /**
     * @var array
     */
    protected $_maxKeySizeMap = [
        self::CIPHER_BLOWFISH => 56,
        self::CIPHER_RIJNDAEL_128 => 32,
        self::CIPHER_RIJNDAEL_256 => 32,
    ];

    /**
     * @var array
     */
    protected $_adapterOptions = [
        self::CIPHER_BLOWFISH => ['\phpseclib\Crypt\Blowfish'],
        self::CIPHER_RIJNDAEL_128 => ['\phpseclib\Crypt\Rijndael', 128],
        self::CIPHER_RIJNDAEL_256 => ['\phpseclib\Crypt\Rijndael', 256],
    ];

    /**
     * @var array
     */
    protected $_adapterModeMap = [
        self::MODE_CBC => Base::MODE_CBC,
        self::MODE_CFB => Base::MODE_CFB,
        self::MODE_CTR => Base::MODE_CTR,
        self::MODE_ECB => Base::MODE_ECB,
        self::MODE_OFB => Base::MODE_OFB,
    ];

    /**
     * Constructor
     *
     * @param  string      $key        Secret encryption key.
     * @param  string      $cipher     Cipher algorithm
     * @param  string      $mode       Mode of cipher algorithm
     * @param  string|bool $initVector Initial vector to fill algorithm blocks.
     *                                 TRUE generates a random initial vector.
     *                                 FALSE fills initial vector with zero bytes to not use it.
     * @throws \Exception
     */
    public function __construct($key, $cipher = self::CIPHER_BLOWFISH, $mode = self::MODE_ECB, $initVector = false)
    {
        if (!isset($this->_adapterOptions[$cipher])) {
            throw new \Magento\Framework\Exception\LocalizedException(
                new \Magento\Framework\Phrase('Not supported cipher version')
            );
        }
        $this->_cipher = $cipher;

        if (strlen($key) > ($maxKeySize = $this->getMaxKeySize())) {
            throw new \Magento\Framework\Exception\LocalizedException(
                new \Magento\Framework\Phrase('Key must not exceed %1 bytes.', [$maxKeySize])
            );
        }
        $this->_key = $key;

        if (!isset($this->_adapterModeMap[$mode])) {
            throw new \Magento\Framework\Exception\LocalizedException(
                new \Magento\Framework\Phrase('Not supported cipher version')
            );
        }
        $this->_mode = $mode;

        $initVectorSize = $this->getIVLength();

        if (true === $initVector) {
            // Generate a random vector from human-readable characters
            $initVector = '';
            if ($initVectorSize) {
                $initVector = Rand::getString($initVectorSize, null, true);
            }
        } elseif (false === $initVector) {
            // Set vector to zero bytes to not use it
            $initVector = str_repeat("\0", $initVectorSize);
        } elseif (!is_string($initVector) || strlen($initVector) != $initVectorSize) {
            throw new \Magento\Framework\Exception\LocalizedException(
                new \Magento\Framework\Phrase('Init vector must be a string of %1 bytes.', [$initVectorSize])
            );
        }

        $this->_initVector = $initVector;
        $this->_adapter = $this->createAdapter();
    }

    /**
     * Returns an instance of the vendor encryption adapter
     *
     * @return Base
     */
    protected function createAdapter()
    {
        $adapterOptions = $this->_adapterOptions[$this->_cipher];
        $adapterClass = $adapterOptions[0];
        $blockLength = isset($adapterOptions[1]) ? $adapterOptions[1] : 0;
        $adapterMode = $this->_adapterModeMap[$this->_mode];
        $adapter = new $adapterClass($adapterMode);

        if ($blockLength) {
            $adapter->setBlockLength($blockLength);
        }

        $adapter->setKey($this->_key);
        $adapter->setIV($this->_initVector);

        return $adapter;
    }

    /**
     * Retrieve a name of currently used cryptographic algorithm
     *
     * @return string
     */
    public function getCipher()
    {
        return $this->_cipher;
    }

    /**
     * Mode in which cryptographic algorithm is running
     *
     * @return string
     */
    public function getMode()
    {
        return $this->_mode;
    }

    /**
     * Retrieve an actual value of initial vector that has been used to initialize a cipher
     *
     * @return string
     */
    public function getInitVector()
    {
        return $this->_initVector;
    }

    /**
     * Return the maximum key size supported by the cipher
     *
     * @return int
     */
    protected function getMaxKeySize()
    {
        return isset($this->_maxKeySizeMap[$this->_cipher]) ? $this->_maxKeySizeMap[$this->_cipher] : 0;
    }

    /**
     * Return the initialization vector length in bytes needed by the cipher
     *
     * @return int
     */
    protected function getIVLength()
    {
        if ($this->_mode == self::MODE_ECB) {
            return 0;
        }

        return $this->getBlockLength() >> 3;
    }

    /**
     * Return the block length in bits of the cipher
     *
     * @return int
     */
    protected function getBlockLength()
    {
        return isset($this->_blockLengthMap[$this->_cipher]) ? $this->_blockLengthMap[$this->_cipher] : 0;
    }

    /**
     * Encrypt a data
     *
     * @param  string $data String to encrypt
     * @return string
     */
    public function encrypt($data)
    {
        if (empty($data)) {
            return $data;
        }

        return $this->_adapter->encrypt($data);
    }

    /**
     * Decrypt a data
     *
     * @param  string $data String to decrypt
     * @return string
     */
    public function decrypt($data)
    {
        if (empty($data)) {
            return $data;
        }

        $text = $this->_adapter->decrypt($data);

        // backwards compatibility with previously encrypted texts with bad mcrypt null padding
        if ($text === false) {
            $this->_adapter->disablePadding();
            $data = $this->_adapter->decrypt($data);
            $data = rtrim($data, "\0");
            return $data;
        }

        return $text;
    }
}
