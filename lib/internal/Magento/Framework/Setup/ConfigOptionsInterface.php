<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Magento\Framework\Setup;

/**
 * Interface for handling options in deployment configuration tool
 */
interface ConfigOptionsInterface
{
    /**
     * Gets a list of input options so that user can provide required
     * information that will be used in deployment config file
     *
     * @return Option\AbstractConfigOption[]
     */
    public function getOptions();

    /**
     * Creates array of ConfigData objects from user inputted data.
     * Data in these objects will be stored in array form in deployment config file.
     *
     * @param array $options
     * @return \Magento\Framework\Config\Data\ConfigData[]
     * @throws \InvalidArgumentException
     */
    public function createConfig(array $options);
}
