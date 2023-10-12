const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';

async function registerUser(req, res) {
  const { firstname, lastname, email, phone, age, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        firstname,
        lastname,
        email,
        phone,
        age,
        password: hashedPassword,
      },
    });

    res.json({ message: 'User registered successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while registering the user' });
  }
}

async function loginUser(req, res) {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
      res.json({ message: 'Login successful', token });
    } else {
      res.status(401).json({ error: 'Invalid password' });
    }
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while logging in' });
  }
}

async function userProfile(req, res) {
    const userId = req.userId;
  
    try {
      const user = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const welcomeMessage = `Welcome, ${user.firstname} ${user.lastname}!`;
  
      res.json({ message: welcomeMessage, user });
    } catch (error) {
      res.status(500).json({ error: 'An error occurred while fetching user data' });
    }
  }
  
  
  
module.exports = {
  registerUser,
  loginUser,
userProfile,
};
