<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */
?>
<?php return [
  'blowfish' => [
    'ecb' => [
      'key_size' => 56,
      'iv_size' => 0,
    ],
    'cbc' => [
      'key_size' => 56,
      'iv_size' => 8,
    ],
    'cfb' => [
      'key_size' => 56,
      'iv_size' => 8,
    ],
    'ofb' => [
      'key_size' => 56,
      'iv_size' => 8,
    ],
    'ctr' => [
      'key_size' => 56,
      'iv_size' => 8,
    ],
  ],
  'rijndael-128' => [
    'ecb' => [
      'key_size' => 32,
      'iv_size' => 0,
    ],
    'cbc' => [
      'key_size' => 32,
      'iv_size' => 16,
    ],
    'cfb' => [
      'key_size' => 32,
      'iv_size' => 16,
    ],
    'ofb' => [
      'key_size' => 32,
      'iv_size' => 16,
    ],
    'ctr' => [
      'key_size' => 32,
      'iv_size' => 16,
    ],
  ],
  'rijndael-256' => [
    'ecb' => [
      'key_size' => 32,
      'iv_size' => 0,
    ],
    'cbc' => [
      'key_size' => 32,
      'iv_size' => 32,
    ],
    'cfb' => [
      'key_size' => 32,
      'iv_size' => 32,
    ],
    'ofb' => [
      'key_size' => 32,
      'iv_size' => 32,
    ],
    'ctr' => [
      'key_size' => 32,
      'iv_size' => 32,
    ],
  ],
];
