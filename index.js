


const express = require('express');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 2000;

app.use(express.json());

// Import user routes
const userRoutes = require('./routes/userRoutes');

// Use user routes
app.use('/user', userRoutes);




app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
