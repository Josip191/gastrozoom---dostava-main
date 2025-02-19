const express = require('express');
const prisma = require('../config/prisma');
const authenticateToken = require("../middleware/authenticateToken");
const authorizeAdmin = require("../middleware/authorizeAdmin");
const authorizeWorker = require("../middleware/authorizeWorker");
const router = express.Router();

// create new order
router.post('/create', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  const {basketItems, addressId, deliveryPrice} = req.body;

  if (!userId || !basketItems || !addressId || !deliveryPrice) {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  try {
    const address = await prisma.address.findUnique({
      where: {
        id: addressId,
      },
    });

    if (!address) {
      return res.status(404).json({ error: 'Adresa nije pronađena' });
    }

    let totalPrice = deliveryPrice;
    const orderItemsData = [];

    for (const foodItem of basketItems) {
      const food = await prisma.food.findUnique({
        where: {
          id: Number(foodItem.foodId),
        },
      });

      if (!food) {
        return res.status(404).json({ error: `Hrana s ID-em ${foodId} nije pronađena` });
      }

      const quantity = foodItem.quantity;
      const itemTotalPrice = food.price * quantity;
      totalPrice += itemTotalPrice;

      orderItemsData.push({
        foodId: food.id,
        foodName: food.name,
        foodPrice: food.price,
        quantity,
        totalPrice: itemTotalPrice,
      });
    }

    const newOrder = await prisma.order.create({
      data: {
        user: {
          connect: {id: userId},
        },
        addressId: addressId,
        address: address.address,
        addressNumber: address.addressNumber,
        floorNumber: address.floorNumber,
        totalPrice,
        orderItems: {
          create: orderItemsData,
        },
      },
    });

    res.status(201).json(newOrder);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Kreiranje narudžbe nije uspjelo' });
  }
});

// get all orders
router.get('/all', authenticateToken, authorizeAdmin, async function (req, res) {
  try {
    const orders = await prisma.order.findMany({

      
    });

    res.status(200).json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Dohvat narudžbi nije uspio' });
  }
});

// get all user orders
router.get('/user-all', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  try {
    const orders = await prisma.order.findMany({
      where: {
        userId,
      },
    });

    res.status(200).json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Dohvat narudžbi nije uspio' });
  }
});

// get order by id
router.get('/:id', async function (req, res) {
  const { id } = req.params;

  try {
    const order = await prisma.order.findUnique({
      where: {
        id: Number(id),
      },
    });

    res.status(200).json(order);
  } catch (error) {
    res.status(500).json({ error: 'Dohvat narudžbe nije uspio' });
  }
});

// update order by id
router.put('/:id', authenticateToken, authorizeWorker, async function (req, res) {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status je obavezan' });
  }

  try {
    const updatedOrder = await prisma.order.update({
      where: {
        id: Number(id),
      },
      data: {
        status,
      },
    });

    const translatedStatus = () => {
      switch (status) {
        case 'ACCEPTED':
          return 'prihvaćena';
        case 'REJECTED':
          return 'odbijena';
        case 'IN_DELIVERY':
          return 'u pripremi';
        case 'DELIVERED':
          return 'isporučena';
        default:
          return '';
      }
    }

    await prisma.message.create({
      data: {
        userId: updatedOrder.userId,
        title: 'Status narudžbe',
        text: `Vaša narudžba ${updatedOrder.id} je ${translatedStatus()}`,
        type: `ORDER_${status}`,
      },
    });

    res.status(200).json(updatedOrder);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Ažuriranje narudžbe nije uspjelo' });
  }
});

module.exports = router;