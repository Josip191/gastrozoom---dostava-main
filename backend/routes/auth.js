const express = require('express');
const prisma = require('../config/prisma');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const router = express.Router();
const authenticateToken = require('../middleware/authenticateToken');
const authorizeAdmin = require('../middleware/authorizeAdmin');

dotenv.config();

// register new user
router.post('/register', async function(req, res) {
  const { name, phoneNumber, email, password, role } = req.body;

  if (name.trim() === '' || phoneNumber.trim() === '' || email.trim() === '' || password.trim() === '') {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Lozinka mora imati najmanje 6 znakova' });
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: {
        email,
      },
    });
    if (existingUser) {
      return res.status(400).json({ error: 'Korisnik s ovim emailom već postoji' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        name,
        phoneNumber,
        email,
        password: hashedPassword,
        role: role || 'USER',
      },
    });

    const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, process.env.JWT_SECRET);

    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Registracija nije uspjela'})
  }
});

// login user
router.post('/login', async function(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return res.status(400).json({ error: 'Neispravni podaci za prijavu' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(400).json({ error: 'Neispravni podaci za prijavu' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET);

    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Prijava nije uspjela' });
  }
});

// get user data
router.get('/me', authenticateToken, async function(req, res) {
  const token = req.headers.authorization.split(' ')[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: decoded.id,
      },
      select: {
        id: true,
        name: true,
        phoneNumber: true,
        email: true,
        role: true,
      },
    });

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Nemoguće dohvatiti podatke korisnika' });
  }
});

// get user data by id
router.get('/:id', authenticateToken, authorizeAdmin, async function(req, res) {
  const { id } = req.params;

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: Number(id),
      },
      select: {
        id: true,
        name: true,
        phoneNumber: true,
        email: true,
        role: true,
      },
    });

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Nemoguće dohvatiti podatke korisnika' });
  }
});

// update user data
router.put('/:id', authenticateToken, authorizeAdmin, async function(req, res) {
  const { id } = req.params;
  const { name, phoneNumber, email, role } = req.body;

  if (!name || !phoneNumber || !email) {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  try {
    const updatedUser = await prisma.user.update({
      where: {
        id: Number(id),
      },
      data: {
        name,
        phoneNumber,
        email,
        role,
      },
    });

    res.status(200).json({ user: updatedUser });
  } catch (error) {
    res.status(500).json({ error: 'Ažuriranje podataka korisnika nije uspjelo' });
  }
});

// logout user
router.delete('/logout', authenticateToken, async function(req, res) {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    await prisma.revokedToken.create({
      data: { token },
    });
  }
  res.status(200).json({ error: 'Korisnik se uspješno odjavio'});
});

module.exports = router;
