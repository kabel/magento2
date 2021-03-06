<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Magento\Swatches\Block\Product\Renderer;

use Magento\Catalog\Block\Product\Context;
use Magento\Catalog\Helper\Product as CatalogProduct;
use Magento\ConfigurableProduct\Helper\Data;
use Magento\ConfigurableProduct\Model\ConfigurableAttributeData;
use Magento\Customer\Helper\Session\CurrentCustomer;
use Magento\Framework\Json\EncoderInterface;
use Magento\Framework\Pricing\PriceCurrencyInterface;
use Magento\Catalog\Model\Product;
use Magento\Framework\Stdlib\ArrayUtils;
use Magento\Store\Model\ScopeInterface;
use Magento\Swatches\Helper\Data as SwatchData;
use Magento\Swatches\Helper\Media;
use Magento\Swatches\Model\Swatch;

/**
 * Swatch renderer block
 *
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class Configurable extends \Magento\ConfigurableProduct\Block\Product\View\Type\Configurable
{
    /**
     * Path to template file with Swatch renderer.
     */
    const SWATCH_RENDERER_TEMPLATE = 'Magento_Swatches::product/view/renderer.phtml';

    /**
     * Path to default template file with standard Configurable renderer.
     */
    const CONFIGURABLE_RENDERER_TEMPLATE = 'Magento_ConfigurableProduct::product/view/type/options/configurable.phtml';

    /**
     * When we init media gallery empty image types contain this value.
     */
    const EMPTY_IMAGE_VALUE = 'no_selection';

    /**
     * Action name for ajax request
     */
    const MEDIA_CALLBACK_ACTION = 'swatches/ajax/media';

    /**
     * @var Product
     */
    protected $product;

    /**
     * @var SwatchData
     */
    protected $swatchHelper;

    /**
     * @var Media
     */
    protected $swatchMediaHelper;

    /**
     * Indicate if product has one or more Swatch attributes
     *
     * @var boolean
     */
    protected $isProductHasSwatchAttribute;

    /**
     * @param Context $context
     * @param ArrayUtils $arrayUtils
     * @param EncoderInterface $jsonEncoder
     * @param Data $helper
     * @param CatalogProduct $catalogProduct
     * @param CurrentCustomer $currentCustomer
     * @param PriceCurrencyInterface $priceCurrency
     * @param ConfigurableAttributeData $configurableAttributeData
     * @param SwatchData $swatchHelper
     * @param Media $swatchMediaHelper
     * @param array $data other data
     * @SuppressWarnings(PHPMD.ExcessiveParameterList)
     */
    public function __construct(
        Context $context,
        ArrayUtils $arrayUtils,
        EncoderInterface $jsonEncoder,
        Data $helper,
        CatalogProduct $catalogProduct,
        CurrentCustomer $currentCustomer,
        PriceCurrencyInterface $priceCurrency,
        ConfigurableAttributeData $configurableAttributeData,
        SwatchData $swatchHelper,
        Media $swatchMediaHelper,
        array $data = []
    ) {
        $this->swatchHelper = $swatchHelper;
        $this->swatchMediaHelper = $swatchMediaHelper;

        parent::__construct(
            $context,
            $arrayUtils,
            $jsonEncoder,
            $helper,
            $catalogProduct,
            $currentCustomer,
            $priceCurrency,
            $configurableAttributeData,
            $data
        );
    }

    /**
     * Get Swatch config data
     *
     * @return string
     */
    public function getJsonSwatchConfig()
    {
        $attributesData = $this->getSwatchAttributesData();
        $allOptionIds = $this->getAllOptionsIdsFromAttributeArray($attributesData);
        $swatchesData = $this->swatchHelper->getSwatchesByOptionsId($allOptionIds);

        $config = [];
        foreach ($attributesData as $attributeId => $attributeDataArray) {
            if (isset($attributeDataArray['options'])) {
                $config[$attributeId] = $this->addSwatchDataForAttribute(
                    $attributeDataArray['options'],
                    $swatchesData,
                    $attributeDataArray
                );
            }
        }

        return $this->jsonEncoder->encode($config);
    }

    /**
     * Get number of swatches from config to show on product listing.
     * Other swatches can be shown after click button 'Show more'
     *
     * @return string
     */
    public function getNumberSwatchesPerProduct()
    {
        return $this->_scopeConfig->getValue(
            'catalog/frontend/swatches_per_product',
            ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Set product to block
     *
     * @param Product $product
     * @return $this
     */
    public function setProduct(Product $product)
    {
        $this->product = $product;
        return $this;
    }

    /**
     * Override parent function
     *
     * @return Product
     */
    public function getProduct()
    {
        if (!$this->product) {
            $this->product = parent::getProduct();
        }

        return $this->product;
    }

    /**
     * @return array
     */
    protected function getSwatchAttributesData()
    {
        return $this->swatchHelper->getSwatchAttributesAsArray($this->getProduct());
    }

    /**
     * @codeCoverageIgnore
     * @return void
     */
    protected function initIsProductHasSwatchAttribute()
    {
        $this->isProductHasSwatchAttribute = $this->swatchHelper->isProductHasSwatch($this->getProduct());
    }

    /**
     * Add Swatch Data for attribute
     *
     * @param array $options
     * @param array $swatchesCollectionArray
     * @param array $attributeDataArray
     * @return array
     */
    protected function addSwatchDataForAttribute(
        array $options,
        array $swatchesCollectionArray,
        array $attributeDataArray
    ) {
        $result = [];
        foreach ($options as $optionId => $label) {
            if (isset($swatchesCollectionArray[$optionId])) {
                $result[$optionId]['label'] = $label;
                $result[$optionId] = $this->extractNecessarySwatchData($swatchesCollectionArray[$optionId]);
                $result[$optionId] = $this->addAdditionalMediaData($result[$optionId], $optionId, $attributeDataArray);
            }
        }

        return $result;
    }

    /**
     * Add media from variation
     *
     * @param array $swatch
     * @param integer $optionId
     * @param array $attributeDataArray
     * @return array
     */
    protected function addAdditionalMediaData(array $swatch, $optionId, array $attributeDataArray)
    {
        if (
            isset($attributeDataArray['use_product_image_for_swatch'])
            && $attributeDataArray['use_product_image_for_swatch']
        ) {
            $variationMedia = $this->getVariationMedia($attributeDataArray['attribute_code'], $optionId);
            if (! empty($variationMedia)) {
                $swatch['type'] = Swatch::SWATCH_TYPE_VISUAL_IMAGE;
                $swatch = array_merge($swatch, $variationMedia);
            }
        }
        return $swatch;
    }

    /**
     * Retrieve Swatch data for config
     *
     * @param array $swatchDataArray
     * @return array
     */
    protected function extractNecessarySwatchData(array $swatchDataArray)
    {
        $result['type'] = $swatchDataArray['type'];

        if ($result['type'] == Swatch::SWATCH_TYPE_VISUAL_IMAGE && !empty($swatchDataArray['value'])) {
            $result['value'] = $this->swatchMediaHelper->getSwatchAttributeImage(
                'swatch_image',
                $swatchDataArray['value']
            );
            $result['thumb'] = $this->swatchMediaHelper->getSwatchAttributeImage(
                'swatch_thumb',
                $swatchDataArray['value']
            );
        } else {
            $result['value'] = $swatchDataArray['value'];
        }

        return $result;
    }

    /**
     * Generate Product Media array
     *
     * @param string $attributeCode
     * @param integer $optionId
     * @return array
     */
    protected function getVariationMedia($attributeCode, $optionId)
    {
        $variationProduct = $this->swatchHelper->loadFirstVariationWithSwatchImage(
            $this->getProduct(),
            [$attributeCode => $optionId]
        );

        $variationMediaArray = [];
        if ($variationProduct) {
            $swatchConfig = $this->swatchMediaHelper->getImageConfig();
            $variationMediaArray = [
                'value' => $this->getSwatchProductImage(
                    $variationProduct,
                    $swatchConfig['swatch_image:width'],
                    $swatchConfig['swatch_image:height']
                ),
                'thumb' => $this->getSwatchProductImage(
                    $variationProduct,
                    $swatchConfig['swatch_thumb:width'],
                    $swatchConfig['swatch_thumb:height']
                ),
            ];
        }

        return $variationMediaArray;
    }

    /**
     * @param Product $childProduct
     * @param integer $width
     * @param integer $height
     * @return string
     */
    protected function getSwatchProductImage(Product $childProduct, $width, $height)
    {
        if (
            $childProduct->getData('swatch_image') !== null
            && $childProduct->getData('swatch_image') != self::EMPTY_IMAGE_VALUE
        ) {
            $swatchContainer = 'swatch_image';
        } elseif (
            $childProduct->getData('image') !== null
            && $childProduct->getData('image') != self::EMPTY_IMAGE_VALUE
        ) {
            $swatchContainer = 'image';
        }
        if (isset($swatchContainer)) {
            return (string)$this->_imageHelper->init($childProduct, $swatchContainer)->resize($width, $height);
        }
    }

    /**
     * @param array $attributeData
     * @return array
     */
    protected function getAllOptionsIdsFromAttributeArray(array $attributeData)
    {
        $ids = [];
        foreach ($attributeData as $item) {
            if (isset($item['options'])) {
                $ids = array_merge($ids, array_keys($item['options']));
            }
        }
        return $ids;
    }

    /**
     * Return HTML code
     *
     * @codeCoverageIgnore
     * @return string
     */
    protected function _toHtml()
    {
        $this->initIsProductHasSwatchAttribute();
        $this->setTemplate(
            $this->getRendererTemplate()
        );

        return $this->getHtmlOutput();
    }

    /**
     * @codeCoverageIgnore
     * @return string
     */
    protected function getRendererTemplate()
    {
        return $this->isProductHasSwatchAttribute ?
            self::SWATCH_RENDERER_TEMPLATE : self::CONFIGURABLE_RENDERER_TEMPLATE;
    }

    /**
     * @codeCoverageIgnore
     * @return string
     */
    protected function getHtmlOutput()
    {
        return parent::_toHtml();
    }

    /**
     * @return string
     */
    public function getMediaCallback()
    {
        return $this->getBaseUrl() . self::MEDIA_CALLBACK_ACTION;
    }
}
