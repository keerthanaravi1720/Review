

const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 2000;

app.use(express.json());

app.post('/register', async (req, res) => {
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
});


const jwtSecret = process.env.JWT_SECRET || 'your-secret-key';

app.post('/login', async (req, res) => {
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
      res.json({ message: 'Login successful', token }); // Sending token only
    } else {
      res.status(401).json({ error: 'Invalid password' });
    }
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while logging in' });
  }
});

// Token Verification Middleware
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  jwt.verify(token.replace('Bearer ', ''), jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }

    // If the token is valid, store the user ID in the request for further processing
    req.userId = decoded.userId;
    next();
  });
}


app.get('/profile', verifyToken, async (req, res) => {
  // Access the user's ID using req.userId
  const userId = req.userId;

  try {
    // Fetch user data
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
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
