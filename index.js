


require('dotenv').config(); 
const express = require('express');
const mysql = require('mysql2/promise'); 
const cors = require('cors');           
const morgan = require('morgan');       
const SHA256 = require('crypto-js/sha256'); 


const app = express();
const port = process.env.API_PORT || 3000; 


app.use(cors()); 
app.use(morgan('dev')); 
app.use(express.json()); 


const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10, 
  queueLimit: 0
});


pool.getConnection()
  .then(connection => {
    console.log('Database connected successfully!');
    connection.release(); 
  })
  .catch(err => {
    console.error('Error connecting to database:', err.message);
    
    process.exit(1);
  });



function hashPassword(password) {
    
    
    return SHA256(password + process.env.SECRET_KEY).toString();
}




app.get('/', (req, res) => {
  res.send('Hello World! Welcome to the API.');
});

app.get('/marco', (req, res) => {
  res.send('polo'); 
});

app.get('/ping', (req, res) => {
  
  pool.query('SELECT 1')
    .then(() => {
      res.json({ message: 'pong', database_status: 'connected' });
    })
    .catch(err => {
      res.status(503).json({ message: 'pong', database_status: 'error', error: err.message }); 
    });
});




app.get('/users', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, created_at FROM users'); 
    res.json(rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: 'Error retrieving users', error: error.message });
  }
});


app.get('/users/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const [rows] = await pool.query('SELECT id, name, email, created_at FROM users WHERE id = ?', [userId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error(`Error fetching user ${userId}:`, error);
    res.status(500).json({ message: 'Error retrieving user', error: error.message });
  }
});


app.post('/users', async (req, res) => {
  const { name, email, password } = req.body;

  
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Missing required fields: name, email, password' });
  }

  try {
    
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
        return res.status(409).json({ message: 'Email already in use' }); 
    }

    
    const hashedPassword = hashPassword(password);

    
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    
    res.status(201).json({ 
        message: 'User created successfully',
        userId: result.insertId,
        name: name,
        email: email
    });
  } catch (error) {
    console.error("Error creating user:", error);
    
    if (error.code === 'ER_DUP_ENTRY') {
         return res.status(409).json({ message: 'Email already in use' });
    }
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});


app.put('/users/:id', async (req, res) => {
  const userId = req.params.id;
  const { name, email, password } = req.body;

  
  if (!name && !email && !password) {
    return res.status(400).json({ message: 'No fields provided for update' });
  }

  try {
    
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    
    if (email) {
        const [existingEmails] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, userId]);
        if (existingEmails.length > 0) {
            return res.status(409).json({ message: 'Email already in use by another user' });
        }
    }

    
    let query = 'UPDATE users SET ';
    const params = [];
    if (name) {
      query += 'name = ?, ';
      params.push(name);
    }
    if (email) {
      query += 'email = ?, ';
      params.push(email);
    }
    if (password) {
      query += 'password_hash = ?, ';
      params.push(hashPassword(password)); 
    }

    
    query = query.slice(0, -2);
    query += ' WHERE id = ?';
    params.push(userId);

    
    const [result] = await pool.query(query, params);

    if (result.affectedRows === 0) {
        
         return res.status(404).json({ message: 'User not found or no changes made' });
    }

    res.json({ message: 'User updated successfully', id: userId });

  } catch (error) {
    console.error(`Error updating user ${userId}:`, error);
     if (error.code === 'ER_DUP_ENTRY') {
         return res.status(409).json({ message: 'Email already in use by another user' });
    }
    res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});


app.delete('/users/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [userId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'User deleted successfully', id: userId }); 
  } catch (error) {
    console.error(`Error deleting user ${userId}:`, error);
    res.status(500).json({ message: 'Error deleting user', error: error.message });
  }
});




app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    
    const [users] = await pool.query('SELECT id, name, email, password_hash FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' }); 
    }

    const user = users[0];

    
    const hashedInputPassword = hashPassword(password);

    if (hashedInputPassword !== user.password_hash) {
      return res.status(401).json({ message: 'Invalid credentials' }); 
    }

    
    
    
    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
      
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: 'Login failed due to server error', error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
