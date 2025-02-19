const express = require('express');
const prisma = require('../config/prisma');
const authenticateToken = require("../middleware/authenticateToken");
const router = express.Router();

// create new address
router.post('/create', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  const {address, addressNumber, floorNumber, isSelectedOnDoor} = req.body;
  let {isPrimary} = req.body;

  if (!userId || !address) {
    return res.status(400).json({error: 'Sva polja su obavezna'});
  }

  const primaryExists = await prisma.address.findFirst({
    where: {
      userId,
      isPrimary: true,
    },
  });

  if (isPrimary === false && primaryExists === null) {
    isPrimary = true;
  }

  try {
    const newAddress = await prisma.address.create({
      data: {
        user: {
          connect: {
            id: userId,
          },
        },
        address,
        addressNumber,
        floorNumber,
        isSelectedOnDoor,
        isPrimary,
      },
    });

    res.status(201).json(newAddress);
  } catch (error) {
    res.status(500).json({error: 'Greška u kreiranju adrese'});
  }
});

// get all addresses
router.get('/all', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  try {
    const addresses = await prisma.address.findMany({
      where: {
        userId,
      },
    });

    res.status(200).json(addresses);
  } catch (error) {
    res.status(500).json({error: 'Greška u dohvatanju adresa'});
  }
});

// get address with isPrimary true
router.get('/primary', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  try {
    const address = await prisma.address.findFirst({
      where: {
        userId,
        isPrimary: true,
      },
    });

    res.status(200).json(address);
  } catch (error) {
    res.status(500).json({error: 'Greška u dohvatanju adrese'});
  }
});

// get address by id
router.get('/:id', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  const {id} = req.params;

  try {
    const address = await prisma.address.findUnique({
      where: {
        userId,
        id: Number(id),
      },
    });

    res.status(200).json(address);
  } catch (error) {
    res.status(500).json({error: 'Greška u dohvatanju adrese'});
  }
});

// update address by id
router.put('/:id', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  const {id} = req.params;
  const {address, addressNumber, floorNumber, isPrimary, isSelectedOnDoor } = req.body;

  if (!address) {
    return res.status(400).json({error: 'Adresa je obavezna'});
  }

  try {
    const updatedAddress = await prisma.address.update({
      where: {
        userId,
        id: Number(id),
      },
      data: {
        address,
        addressNumber,
        floorNumber,
        isSelectedOnDoor,
        isPrimary,
      },
    });

    res.status(200).json(updatedAddress);
  } catch (error) {
    res.status(500).json({error: 'Greška u ažuriranju adrese'});
  }
});

// delete address by id
router.delete('/:id', authenticateToken, async function (req, res) {
  const userId = req.user.id;
  const {id} = req.params;

  try {
    await prisma.address.delete({
      where: {
        userId,
        id: Number(id),
      },
    });

    res.status(200).json({message: 'Adresa je uspešno obrisana'});
  } catch (error) {
    res.status(500).json({error: 'Greška u brisanju adrese'});
  }
});

module.exports = router;