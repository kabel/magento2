<?php
/**
 * Copyright © 2015 Magento. All rights reserved.
 * See COPYING.txt for license details.
 */

namespace Magento\Sales\Test\Unit\Controller\Adminhtml\Order;

use Magento\Framework\App\Action\Context;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager as ObjectManagerHelper;

/**
 * Class MassHoldTest
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class MassHoldTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Magento\Sales\Controller\Adminhtml\Order\MassHold
     */
    protected $massAction;

    /**
     * @var Context|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $contextMock;

    /**
     * @var \Magento\Backend\Model\View\Result\Redirect|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $resultRedirectMock;

    /**
     * @var \Magento\Framework\App\Request\Http|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $requestMock;

    /**
     * @var \Magento\Framework\App\ResponseInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $responseMock;

    /**
     * @var \Magento\Framework\Message\Manager|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $messageManagerMock;

    /**
     * @var \Magento\Framework\ObjectManager\ObjectManager|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $objectManagerMock;

    /**
     * @var \Magento\Backend\Model\Session|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $sessionMock;

    /**
     * @var \Magento\Framework\App\ActionFlag|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $actionFlagMock;

    /**
     * @var \Magento\Backend\Helper\Data|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $helperMock;

    /**
     * @var \Magento\Sales\Model\Order|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $orderMock;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    protected $orderCollectionMock;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    protected $orderManagement;

    /**
     * @return void
     * @SuppressWarnings(PHPMD.ExcessiveMethodLength)
     */
    public function setUp()
    {
        $objectManagerHelper = new ObjectManagerHelper($this);
        $this->contextMock = $this->getMock(
            'Magento\Backend\App\Action\Context',
            [
                'getRequest',
                'getResponse',
                'getMessageManager',
                'getRedirect',
                'getObjectManager',
                'getSession',
                'getActionFlag',
                'getHelper',
                'getResultRedirectFactory',
                'getResultFactory'
            ],
            [],
            '',
            false
        );
        $resultRedirectFactory = $this->getMock(
            'Magento\Backend\Model\View\Result\RedirectFactory',
            ['create'],
            [],
            '',
            false
        );
        $this->responseMock = $this->getMock(
            'Magento\Framework\App\ResponseInterface',
            ['setRedirect', 'sendResponse'],
            [],
            '',
            false
        );
        $this->requestMock = $this->getMockBuilder('Magento\Framework\App\Request\Http')
            ->disableOriginalConstructor()->getMock();
        $this->objectManagerMock = $this->getMock(
            'Magento\Framework\ObjectManager\ObjectManager',
            [],
            [],
            '',
            false
        );
        $this->messageManagerMock = $this->getMock(
            'Magento\Framework\Message\Manager',
            ['addSuccess', 'addError'],
            [],
            '',
            false
        );
        $this->orderCollectionMock = $this->getMockBuilder('Magento\Sales\Model\Resource\Order\Collection')
            ->disableOriginalConstructor()
            ->getMock();

        $redirectMock = $this->getMockBuilder('Magento\Backend\Model\View\Result\Redirect')
            ->disableOriginalConstructor()
            ->getMock();

        $resultFactoryMock = $this->getMockBuilder('Magento\Framework\Controller\ResultFactory')
            ->disableOriginalConstructor()
            ->getMock();
        $resultFactoryMock->expects($this->any())
            ->method('create')
            ->with(\Magento\Framework\Controller\ResultFactory::TYPE_REDIRECT)
            ->willReturn($redirectMock);

        $this->sessionMock = $this->getMock('Magento\Backend\Model\Session', ['setIsUrlNotice'], [], '', false);
        $this->actionFlagMock = $this->getMock('Magento\Framework\App\ActionFlag', ['get', 'set'], [], '', false);
        $this->helperMock = $this->getMock('\Magento\Backend\Helper\Data', ['getUrl'], [], '', false);
        $this->resultRedirectMock = $this->getMock('Magento\Backend\Model\View\Result\Redirect', [], [], '', false);
        $resultRedirectFactory->expects($this->any())->method('create')->willReturn($this->resultRedirectMock);

        $this->contextMock->expects($this->once())->method('getMessageManager')->willReturn($this->messageManagerMock);
        $this->contextMock->expects($this->once())->method('getRequest')->willReturn($this->requestMock);
        $this->contextMock->expects($this->once())->method('getResponse')->willReturn($this->responseMock);
        $this->contextMock->expects($this->once())->method('getObjectManager')->willReturn($this->objectManagerMock);
        $this->contextMock->expects($this->once())->method('getSession')->willReturn($this->sessionMock);
        $this->contextMock->expects($this->once())->method('getActionFlag')->willReturn($this->actionFlagMock);
        $this->contextMock->expects($this->once())->method('getHelper')->willReturn($this->helperMock);
        $this->contextMock
            ->expects($this->once())
            ->method('getResultRedirectFactory')
            ->willReturn($resultRedirectFactory);
        $this->contextMock->expects($this->any())
            ->method('getResultFactory')
            ->willReturn($resultFactoryMock);

        $this->orderManagement = $this->getMockBuilder('Magento\Sales\Api\OrderManagementInterface')
            ->disableOriginalConstructor()
            ->getMock();
        $this->objectManagerMock->expects($this->any())
            ->method('get')
            ->with('Magento\Sales\Api\OrderManagementInterface')
            ->willReturn($this->orderManagement);
        $this->massAction = $objectManagerHelper->getObject(
            'Magento\Sales\Controller\Adminhtml\Order\MassHold',
            [
                'context' => $this->contextMock,
            ]
        );
    }

    public function testExecuteTwoOrdersPutOnHold()
    {
        $selected = [1, 2];
        $countOrders = count($selected);

        $order1 = $this->getMockBuilder('Magento\Sales\Model\Order')
            ->disableOriginalConstructor()
            ->getMock();
        $order2 = $this->getMockBuilder('Magento\Sales\Model\Order')
            ->disableOriginalConstructor()
            ->getMock();

        $this->requestMock->expects($this->at(0))
            ->method('getParam')
            ->with('selected')
            ->willReturn($selected);

        $this->requestMock->expects($this->at(1))
            ->method('getParam')
            ->with('excluded')
            ->willReturn([]);

        $this->objectManagerMock->expects($this->once())
            ->method('create')
            ->with('Magento\Sales\Model\Resource\Order\Grid\Collection')
            ->willReturn($this->orderCollectionMock);
        $this->orderCollectionMock->expects($this->once())
            ->method('addFieldToFilter')
            ->with(\Magento\Sales\Controller\Adminhtml\Order\MassCancel::ID_FIELD, ['in' => $selected]);
        $this->orderCollectionMock->expects($this->any())
            ->method('getItems')
            ->willReturn([$order1, $order2]);

        $this->orderManagement->expects($this->once())
            ->method('hold')
            ->with(1);
        $order1->expects($this->once())
            ->method('canHold')
            ->willReturn(true);
        $order1->expects($this->once())
            ->method('getEntityId')
            ->willReturn(1);

        $this->orderCollectionMock->expects($this->once())
            ->method('count')
            ->willReturn($countOrders);

        $order2->expects($this->once())
            ->method('canHold')
            ->willReturn(false);

        $this->messageManagerMock->expects($this->once())
            ->method('addError')
            ->with('1 order(s) were not put on hold.');

        $this->messageManagerMock->expects($this->once())
            ->method('addSuccess')
            ->with('You have put 1 order(s) on hold.');

        $this->resultRedirectMock->expects($this->once())
            ->method('setPath')
            ->with('sales/*/')
            ->willReturnSelf();

        $this->massAction->execute();
    }

    public function testExecuteOneOrderCannotBePutOnHold()
    {
        $excluded = [1, 2];
        $countOrders = count($excluded);

        $order1 = $this->getMockBuilder('Magento\Sales\Model\Order')
            ->disableOriginalConstructor()
            ->getMock();
        $order2 = $this->getMockBuilder('Magento\Sales\Model\Order')
            ->disableOriginalConstructor()
            ->getMock();

        $this->requestMock->expects($this->at(0))
            ->method('getParam')
            ->with('selected')
            ->willReturn([]);

        $this->requestMock->expects($this->at(1))
            ->method('getParam')
            ->with('excluded')
            ->willReturn($excluded);

        $this->objectManagerMock->expects($this->once())
            ->method('create')
            ->with('Magento\Sales\Model\Resource\Order\Grid\Collection')
            ->willReturn($this->orderCollectionMock);
        $this->orderCollectionMock->expects($this->once())
            ->method('addFieldToFilter')
            ->with(\Magento\Sales\Controller\Adminhtml\Order\MassCancel::ID_FIELD, ['nin' => $excluded]);
        $this->orderCollectionMock->expects($this->any())
            ->method('getItems')
            ->willReturn([$order1, $order2]);

        $order1->expects($this->once())
            ->method('canHold')
            ->willReturn(false);

        $this->orderCollectionMock->expects($this->once())
            ->method('count')
            ->willReturn($countOrders);

        $order2->expects($this->once())
            ->method('canHold')
            ->willReturn(false);

        $this->messageManagerMock->expects($this->once())
            ->method('addError')
            ->with('No order(s) were put on hold.');

        $this->resultRedirectMock->expects($this->once())
            ->method('setPath')
            ->with('sales/*/')
            ->willReturnSelf();

        $this->massAction->execute();
    }
}
