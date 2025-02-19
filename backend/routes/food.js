const express = require('express');
const prisma = require('../config/prisma');
const router = express.Router();
const authenticateToken = require('../middleware/authenticateToken');
const authorizeAdmin = require('../middleware/authorizeAdmin');

// create new food
router.post('/create', authenticateToken, authorizeAdmin, async function(req, res) {
  const { name, description, price, category, imageUrl } = req.body;

  if (name.trim() === '' || !price) {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  try {
    const newFood = await prisma.food.create({
      data: {
        name,
        description: description || '',
        price: Number(price),
        category: category || 'GLAVNO_JELO',
        imageUrl: imageUrl || ''
      },
    });

    res.status(201).json(newFood);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Kreiranje hrane nije uspjelo' });
  }
});

// get all foods
router.get('/all', async function(req, res) {
  try {
    const foods = await prisma.food.findMany();

    res.status(200).json(foods);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Doahvat hrane nije uspio' });
  }
});

// get food by id
router.get('/:id', async function(req, res) {
  const { id } = req.params;

  try {
    const food = await prisma.food.findUnique({
      where: {
        id: Number(id),
      },
    });

    res.status(200).json(food);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Dohvat hrane nije uspio' });
  }
});

// update food by id
router.put('/:id', authenticateToken, authorizeAdmin, async function(req, res) {
  const { id } = req.params;
  const { name, description, price, category } = req.body;

  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  try {
    const updatedFood = await prisma.food.update({
      where: {
        id: Number(id),
      },
      data: {
        name,
        description,
        price: Number(price),
        category,
      },
    });

    res.status(200).json(updatedFood);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Ažuriranje hrane nije uspjelo' });
  }
});

// delete food by id
router.delete('/:id', authenticateToken, authorizeAdmin, async function(req, res) {
  const { id } = req.params;

  try {
    await prisma.food.delete({
      where: {
        id: Number(id),
      },
    });

    res.status(204).send();
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ error: 'Brisanje hrane nije uspjelo' });
  }
});

module.exports = router;