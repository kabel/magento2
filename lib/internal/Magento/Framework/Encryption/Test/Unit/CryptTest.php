<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Magento\Framework\Encryption\Test\Unit;

use \Magento\Framework\Encryption\Crypt;

class CryptTest extends \PHPUnit_Framework_TestCase
{
    private $_key;

    private static $_cipherInfo;

    protected $_supportedCiphers = [
        Crypt::CIPHER_BLOWFISH,
        Crypt::CIPHER_RIJNDAEL_128,
        Crypt::CIPHER_RIJNDAEL_256,
    ];

    protected $_supportedModes = [
        Crypt::MODE_ECB,
        Crypt::MODE_CBC,
        Crypt::MODE_CFB,
        Crypt::MODE_OFB,
        Crypt::MODE_CTR,
    ];

    protected function setUp()
    {
        $this->_key = substr(__CLASS__, -32, 32);
    }

    protected function _getRandomString($length)
    {
        $result = '';
        if (!$length) {
            return $result;
        }
        do {
            $result .= sha1(microtime());
        } while (strlen($result) < $length);
        return substr($result, -$length);
    }

    protected function _requireCipherInfo()
    {
        $filename = __DIR__ . '/Crypt/_files/_cipher_info.php';
        /* Generate allowed sizes for encryption key and init vector
        $data = [];

        foreach ($this->_supportedCiphers as $cipher) {
            if (!array_key_exists($cipher, $data)) {
                $data[$cipher] = [];
            }

            $key_size = 0;
            $iv_size = 0;

            switch ($cipher) {
                case Crypt::CIPHER_BLOWFISH:
                    $key_size = 56;
                    $iv_size = 8;
                    break;
                case Crypt::CIPHER_RIJNDAEL_128:
                    $key_size = 32;
                    $iv_size = 16;
                    break;
                case Crypt::CIPHER_RIJNDAEL_256:
                    $key_size = 32;
                    $iv_size = 32;
            }

            foreach ($this->_supportedModes as $mode) {
                $data[$cipher][$mode] = [
                    'key_size' => $key_size,
                    'iv_size'  => ($mode == Crypt::MODE_ECB) ? 0 : $iv_size,
                ];
            }
        }

        file_put_contents($filename, '<?php return ' . var_export($data, true) . ";\n", LOCK_EX);
        */
        if (!self::$_cipherInfo) {
            self::$_cipherInfo = include $filename;
        }
    }

    protected function _getKeySize($cipherName, $modeName)
    {
        $this->_requireCipherInfo();
        return self::$_cipherInfo[$cipherName][$modeName]['key_size'];
    }

    protected function _getInitVectorSize($cipherName, $modeName)
    {
        $this->_requireCipherInfo();
        return self::$_cipherInfo[$cipherName][$modeName]['iv_size'];
    }

    public function getCipherModeCombinations()
    {
        $result = [];
        foreach ($this->_supportedCiphers as $cipher) {
            foreach ($this->_supportedModes as $mode) {
                $result[] = [$cipher, $mode];
            }
        }
        return $result;
    }

    /**
     * @dataProvider getCipherModeCombinations
     */
    public function testConstructor($cipher, $mode)
    {
        /* Generate random init vector */
        $initVector = $this->_getRandomString($this->_getInitVectorSize($cipher, $mode));
        $key = substr($this->_key, 0, $this->_getKeySize($cipher, $mode));

        $crypt = new Crypt($key, $cipher, $mode, $initVector);

        $this->assertEquals($cipher, $crypt->getCipher());
        $this->assertEquals($mode, $crypt->getMode());
        $this->assertEquals($initVector, $crypt->getInitVector());
    }

    public function getConstructorExceptionData()
    {
        $result = [];
        foreach ($this->_supportedCiphers as $cipher) {
            foreach ($this->_supportedModes as $mode) {
                $iv_size = $this->_getInitVectorSize($cipher, $mode);
                $tooLongKey = str_repeat('-', $this->_getKeySize($cipher, $mode) + 1);
                $tooLongInitVector = str_repeat('-', $iv_size + 1);
                $result[] = [$tooLongKey, $cipher, $mode, false];
                $result[] = [$this->_key, $cipher, $mode, $tooLongInitVector];

                if ($iv_size) {
                    $tooShortInitVector = str_repeat('-', $iv_size - 1);
                    $result[] = [$this->_key, $cipher, $mode, $tooShortInitVector];
                }
            }
        }
        return $result;
    }

    /**
     * @dataProvider getConstructorExceptionData
     * @expectedException \Magento\Framework\Exception\LocalizedException
     */
    public function testConstructorException($key, $cipher, $mode, $initVector)
    {
        new Crypt($key, $cipher, $mode, $initVector);
    }

    public function testConstructorDefaults()
    {
        $cryptExpected = new Crypt($this->_key, Crypt::CIPHER_BLOWFISH, Crypt::MODE_ECB, false);
        $cryptActual = new Crypt($this->_key);

        $this->assertEquals($cryptExpected->getCipher(), $cryptActual->getCipher());
        $this->assertEquals($cryptExpected->getMode(), $cryptActual->getMode());
        $this->assertEquals($cryptExpected->getInitVector(), $cryptActual->getInitVector());
    }

    public function getCryptData()
    {
        $fixturesFilename = __DIR__ . '/Crypt/_files/_crypt_fixtures.php';
        /* Generate fixtures
        $fixtures = [];
        foreach (['', 'Hello world!!!'] as $inputString) {
            foreach ($this->_supportedCiphers as $cipher) {
                foreach ($this->_supportedModes as $mode) {
                    $randomKey = $this->_getRandomString($this->_getKeySize($cipher, $mode));
                    $randomInitVector = $this->_getRandomString($this->_getInitVectorSize($cipher, $mode));
                    $crypt = new Crypt($randomKey, $cipher, $mode, $randomInitVector);
                    $fixtures[] = [
                        $randomKey, // Encryption key
                        $cipher,
                        $mode,
                        $randomInitVector, // Init vector
                        $inputString, // String to encrypt
                        base64_encode($crypt->encrypt($inputString)) // Store result of encryption as base64
                    ];
                }
            }
        }

        file_put_contents($fixturesFilename, '<?php return ' . var_export($fixtures, true) . ";\n", LOCK_EX);
        */
        $result = include $fixturesFilename;
        /* Restore encoded string back to binary */
        foreach ($result as &$cryptParams) {
            $cryptParams[5] = base64_decode($cryptParams[5]);
        }
        unset($cryptParams);
        return $result;
    }

    /**
     * @dataProvider getCryptData
     */
    public function testEncrypt($key, $cipher, $mode, $initVector, $inputData, $expectedData)
    {
        $crypt = new Crypt($key, $cipher, $mode, $initVector);
        $actualData = $crypt->encrypt($inputData);
        $this->assertEquals($expectedData, $actualData);
    }

    /**
     * @dataProvider getCryptData
     */
    public function testDecrypt($key, $cipher, $mode, $initVector, $expectedData, $inputData)
    {
        $crypt = new Crypt($key, $cipher, $mode, $initVector);
        $actualData = $crypt->decrypt($inputData);
        $this->assertEquals($expectedData, $actualData);
    }

    /**
     * @dataProvider getCipherModeCombinations
     */
    public function testInitVectorRandom($cipher, $mode)
    {
        $key = substr($this->_key, 0, $this->_getKeySize($cipher, $mode));

        $crypt1 = new Crypt($key, $cipher, $mode, true);
        $initVector1 = $crypt1->getInitVector();

        $crypt2 = new Crypt($key, $cipher, $mode, true);
        $initVector2 = $crypt2->getInitVector();

        $expectedSize = $this->_getInitVectorSize($cipher, $mode);
        $this->assertEquals($expectedSize, strlen($initVector1));
        $this->assertEquals($expectedSize, strlen($initVector2));

        if ($expectedSize) {
            $this->assertNotEquals($initVector2, $initVector1);
        }
    }

    /**
     * @dataProvider getCipherModeCombinations
     */
    public function testInitVectorNone($cipher, $mode)
    {
        $key = substr($this->_key, 0, $this->_getKeySize($cipher, $mode));

        $crypt = new Crypt($key, $cipher, $mode, false);
        $actualInitVector = $crypt->getInitVector();

        $expectedInitVector = str_repeat("\0", $this->_getInitVectorSize($cipher, $mode));
        $this->assertEquals($expectedInitVector, $actualInitVector);
    }
}
