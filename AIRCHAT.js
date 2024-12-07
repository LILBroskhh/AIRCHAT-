AIRCHAT
npm init -y
npm install express bcryptjs jsonwebtoken pg multer dotenv
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const multer = require('multer');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
const pool = new Pool({
  user: 'yourdbuser',
  host: 'localhost',
  database: 'airchat',
  password: 'yourdbpassword',
  port: 5432,
});

app.use(express.json());

// Middleware per caricare le immagini (esempio per i profili)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const upload = multer({ storage: storage });

// Registrazione utente
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const query = 'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email';
  const result = await pool.query(query, [username, email, hashedPassword]);
  res.status(201).json(result.rows[0]);
});

// Login utente
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const query = 'SELECT * FROM users WHERE email = $1';
  const result = await pool.query(query, [email]);

  if (result.rows.length === 0) {
    return res.status(400).json({ message: 'User not found' });
  }

  const user = result.rows[0];
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    return res.status(400).json({ message: 'Invalid password' });
  }

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware per autenticazione
const authenticate = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.userId = decoded.userId;
    next();
  });
};

// Esegui l'app
app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  );
  
  CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    content TEXT,
    image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE followers (
    follower_id INT REFERENCES users(id),
    followed_id INT REFERENCES users(id),
    PRIMARY KEY (follower_id, followed_id)
  );
  
  CREATE TABLE likes (
    user_id INT REFERENCES users(id),
    post_id INT REFERENCES posts(id),
    PRIMARY KEY (user_id, post_id)
  );
  
  CREATE TABLE comments (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    post_id INT REFERENCES posts(id),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  npx create-react-app airchat
cd airchat
npm start
// Creazione di un post
app.post('/posts', authenticate, async (req, res) => {
    const { content, imageUrl } = req.body;
    
    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    const query = 'INSERT INTO posts (user_id, content, image_url) VALUES ($1, $2, $3) RETURNING id, user_id, content, image_url, created_at';
    const values = [req.userId, content, imageUrl || null];

    try {
        const result = await pool.query(query, values);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating post' });
    }
});
// Recupera i post nella timeline dell'utente
app.get('/timeline', authenticate, async (req, res) => {
    const query = `
        SELECT p.id, p.user_id, p.content, p.image_url, p.created_at, u.username
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id IN (
            SELECT followed_id FROM followers WHERE follower_id = $1
        )
        ORDER BY p.created_at DESC
        LIMIT 20
    `;
    try {
        const result = await pool.query(query, [req.userId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching timeline' });
    }
});
// Aggiungi un like al post
app.post('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const checkIfLiked = 'SELECT * FROM likes WHERE user_id = $1 AND post_id = $2';
    const result = await pool.query(checkIfLiked, [req.userId, postId]);

    if (result.rows.length > 0) {
        return res.status(400).json({ message: 'You have already liked this post' });
    }

    const query = 'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, postId]);
        res.status(201).json({ message: 'Post liked' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error liking post' });
    }
});

// Rimuovi un like dal post
app.delete('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const query = 'DELETE FROM likes WHERE user_id = $1 AND post_id = $2';
    try {
        await pool.query(query, [req.userId, postId]);
        res.status(200).json({ message: 'Like removed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error removing like' });
    }
});
// Aggiungi un commento a un post
app.post('/comments', authenticate, async (req, res) => {
    const { postId, content } = req.body;

    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    const query = 'INSERT INTO comments (user_id, post_id, content) VALUES ($1, $2, $3) RETURNING id, user_id, post_id, content, created_at';
    try {
        const result = await pool.query(query, [req.userId, postId, content]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error adding comment' });
    }
});

// Recupera i commenti per un post
app.get('/comments/:postId', async (req, res) => {
    const { postId } = req.params;
    const query = `
        SELECT c.id, c.user_id, c.content, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = $1
        ORDER BY c.created_at DESC
    `;
    try {
        const result = await pool.query(query, [postId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching comments' });
    }
});
// Follow un altro utente
app.post('/follow', authenticate, async (req, res) => {
    const { userIdToFollow } = req.body;

    // Verifica che non si stia seguendo se stessi
    if (req.userId === userIdToFollow) {
        return res.status(400).json({ message: 'You cannot follow yourself' });
    }

    // Verifica che non si stia già seguendo l'utente
    const checkFollow = 'SELECT * FROM followers WHERE follower_id = $1 AND followed_id = $2';
    const result = await pool.query(checkFollow, [req.userId, userIdToFollow]);

    if (result.rows.length > 0) {
        return res.status(400).json({ message: 'You are already following this user' });
    }

    const query = 'INSERT INTO followers (follower_id, followed_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, userIdToFollow]);
        res.status(201).json({ message: 'User followed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error following user' });
    }
});

// Unfollow un altro utente
app.delete('/follow', authenticate, async (req, res) => {
    const { userIdToUnfollow } = req.body;

    const query = 'DELETE FROM followers WHERE follower_id = $1 AND followed_id = $2';
    try {
        await pool.query(query, [req.userId, userIdToUnfollow]);
        res.status(200).json({ message: 'User unfollowed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error unfollowing user' });
    }
});
npm install socket.io
const http = require('http');
const socketIo = require('socket.io');

const server = http.createServer(app);
const io = socketIo(server);

io.on('connection', (socket) => {
    console.log('A user connected');
    
    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

app.post('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const query = 'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, postId]);
        
        // Emit a notification when someone likes a post
        io.emit('like', { userId: req.userId, postId });

        res.status(201).json({ message: 'Post liked' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error liking post' });
    }
});
// Creazione di un post
app.post('/posts', authenticate, async (req, res) => {
    const { content, imageUrl } = req.body;
    
    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    const query = 'INSERT INTO posts (user_id, content, image_url) VALUES ($1, $2, $3) RETURNING id, user_id, content, image_url, created_at';
    const values = [req.userId, content, imageUrl || null];

    try {
        const result = await pool.query(query, values);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating post' });
    }
});
// Recupera i post nella timeline dell'utente
app.get('/timeline', authenticate, async (req, res) => {
    const query = `
        SELECT p.id, p.user_id, p.content, p.image_url, p.created_at, u.username
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id IN (
            SELECT followed_id FROM followers WHERE follower_id = $1
        )
        ORDER BY p.created_at DESC
        LIMIT 20
    `;
    try {
        const result = await pool.query(query, [req.userId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching timeline' });
    }
});
// Aggiungi un like al post
app.post('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const checkIfLiked = 'SELECT * FROM likes WHERE user_id = $1 AND post_id = $2';
    const result = await pool.query(checkIfLiked, [req.userId, postId]);

    if (result.rows.length > 0) {
        return res.status(400).json({ message: 'You have already liked this post' });
    }

    const query = 'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, postId]);
        res.status(201).json({ message: 'Post liked' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error liking post' });
    }
});

// Rimuovi un like dal post
app.delete('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const query = 'DELETE FROM likes WHERE user_id = $1 AND post_id = $2';
    try {
        await pool.query(query, [req.userId, postId]);
        res.status(200).json({ message: 'Like removed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error removing like' });
    }
});
// Aggiungi un commento a un post
app.post('/comments', authenticate, async (req, res) => {
    const { postId, content } = req.body;

    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    const query = 'INSERT INTO comments (user_id, post_id, content) VALUES ($1, $2, $3) RETURNING id, user_id, post_id, content, created_at';
    try {
        const result = await pool.query(query, [req.userId, postId, content]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error adding comment' });
    }
});

// Recupera i commenti per un post
app.get('/comments/:postId', async (req, res) => {
    const { postId } = req.params;
    const query = `
        SELECT c.id, c.user_id, c.content, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = $1
        ORDER BY c.created_at DESC
    `;
    try {
        const result = await pool.query(query, [postId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching comments' });
    }
});
// Follow un altro utente
app.post('/follow', authenticate, async (req, res) => {
    const { userIdToFollow } = req.body;

    // Verifica che non si stia seguendo se stessi
    if (req.userId === userIdToFollow) {
        return res.status(400).json({ message: 'You cannot follow yourself' });
    }

    // Verifica che non si stia già seguendo l'utente
    const checkFollow = 'SELECT * FROM followers WHERE follower_id = $1 AND followed_id = $2';
    const result = await pool.query(checkFollow, [req.userId, userIdToFollow]);

    if (result.rows.length > 0) {
        return res.status(400).json({ message: 'You are already following this user' });
    }

    const query = 'INSERT INTO followers (follower_id, followed_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, userIdToFollow]);
        res.status(201).json({ message: 'User followed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error following user' });
    }
});

// Unfollow un altro utente
app.delete('/follow', authenticate, async (req, res) => {
    const { userIdToUnfollow } = req.body;

    const query = 'DELETE FROM followers WHERE follower_id = $1 AND followed_id = $2';
    try {
        await pool.query(query, [req.userId, userIdToUnfollow]);
        res.status(200).json({ message: 'User unfollowed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error unfollowing user' });
    }
});
npm install socket.io
const http = require('http');
const socketIo = require('socket.io');

const server = http.createServer(app);
const io = socketIo(server);

io.on('connection', (socket) => {
    console.log('A user connected');
    
    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

app.post('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const query = 'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, postId]);
        
        // Emit a notification when someone likes a post
        io.emit('like', { userId: req.userId, postId });

        res.status(201).json({ message: 'Post liked' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error liking post' });
    }
});
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id INT REFERENCES users(id),
    receiver_id INT REFERENCES users(id),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Invia un messaggio diretto
app.post('/messages', authenticate, async (req, res) => {
    const { receiverId, content } = req.body;

    if (!content || !receiverId) {
        return res.status(400).json({ message: 'Receiver ID and content are required' });
    }

    // Verifica che l'utente non stia inviando un messaggio a se stesso
    if (req.userId === receiverId) {
        return res.status(400).json({ message: 'You cannot send a message to yourself' });
    }

    const query = 'INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING id, sender_id, receiver_id, content, created_at';
    try {
        const result = await pool.query(query, [req.userId, receiverId, content]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error sending message' });
    }
});
// Recupera la cronologia dei messaggi tra due utenti
app.get('/messages/:receiverId', authenticate, async (req, res) => {
    const { receiverId } = req.params;

    // Verifica che l'utente non stia cercando di recuperare messaggi con se stesso
    if (req.userId === parseInt(receiverId)) {
        return res.status(400).json({ message: 'Cannot view messages with yourself' });
    }

    const query = `
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.created_at, u.username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = $1 AND m.receiver_id = $2) OR (m.sender_id = $2 AND m.receiver_id = $1)
        ORDER BY m.created_at ASC
    `;
    try {
        const result = await pool.query(query, [req.userId, receiverId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching messages' });
    }
});
npm install firebase-admin
const admin = require('firebase-admin');
const serviceAccount = require('./path-to-service-account-file.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

const sendPushNotification = async (userId, message) => {
    // Ottieni il token di FCM per l'utente (supponiamo che sia salvato nel database)
    const query = 'SELECT fcm_token FROM users WHERE id = $1';
    const result = await pool.query(query, [userId]);

    if (result.rows.length === 0) {
        return;
    }

    const fcmToken = result.rows[0].fcm_token;

    // Invia la notifica push
    const messagePayload = {
        notification: {
            title: 'Nuova notifica in AIRCHAT',
            body: message,
        },
        token: fcmToken,
    };

    admin.messaging().send(messagePayload)
        .then(response => {
            console.log('Notifica inviata con successo:', response);
        })
        .catch(error => {
            console.error('Errore nell\'invio della notifica:', error);
        });
};
app.post('/likes', authenticate, async (req, res) => {
    const { postId } = req.body;

    const query = 'SELECT user_id FROM posts WHERE id = $1';
    const post = await pool.query(query, [postId]);

    if (post.rows.length === 0) {
        return res.status(404).json({ message: 'Post not found' });
    }

    const postOwnerId = post.rows[0].user_id;

    // Aggiungi il like al post
    const insertLike = 'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)';
    try {
        await pool.query(insertLike, [req.userId, postId]);

        // Invia una notifica all'autore del post
        const message = `L'utente ${req.userId} ha messo like al tuo post!`;
        sendPushNotification(postOwnerId, message);

        res.status(201).json({ message: 'Post liked' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error liking post' });
    }
});
npm install multer
const multer = require('multer');
const storage = multer.memoryStorage(); // Usato per caricare in memoria
const upload = multer({ storage: storage });
// Endpoint per creare un post con immagine/video
app.post('/posts', authenticate, upload.single('media'), async (req, res) => {
    const { content } = req.body;
    const file = req.file;

    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    let mediaUrl = null;

    // Se c'è un file, carichiamo su S3 (esempio base)
    if (file) {
        // Configurazione di AWS S3 (assicurati di configurare la tua access key)
        const AWS = require('aws-sdk');
        const s3 = new AWS.S3();
        const params = {
            Bucket: 'your-s3-bucket',
            Key: `${Date.now()}-${file.originalname}`,
            Body: file.buffer,
            ContentType: file.mimetype,
            ACL: 'public-read',
        };

        try {
            const s3Response = await s3.upload(params).promise();
            mediaUrl = s3Response.Location;
        } catch (err) {
            return res.status(500).json({ message: 'Error uploading media to S3' });
        }
    }

    // Salviamo il post nel database
    const query = 'INSERT INTO posts (user_id, content, image_url) VALUES ($1, $2, $3) RETURNING id, content, image_url';
    try {
        const result = await pool.query(query, [req.userId, content, mediaUrl]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating post' });
    }
});
CREATE TABLE stories (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    media_url TEXT,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);
// Creazione di una storia
app.post('/stories', authenticate, upload.single('media'), async (req, res) => {
    const { content } = req.body;
    const file = req.file;

    if (!content && !file) {
        return res.status(400).json({ message: 'Content or media is required' });
    }

    let mediaUrl = null;
    if (file) {
        // Se c'è un file, carichiamo su S3 (o altro servizio di storage)
        const AWS = require('aws-sdk');
        const s3 = new AWS.S3();
        const params = {
            Bucket: 'your-s3-bucket',
            Key: `${Date.now()}-${file.originalname}`,
            Body: file.buffer,
            ContentType: file.mimetype,
            ACL: 'public-read',
        };

        try {
            const s3Response = await s3.upload(params).promise();
            mediaUrl = s3Response.Location;
        } catch (err) {
            return res.status(500).json({ message: 'Error uploading media to S3' });
        }
    }

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // La storia scade dopo 24 ore

    const query = 'INSERT INTO stories (user_id, content, media_url, expires_at) VALUES ($1, $2, $3, $4) RETURNING id, content, media_url, created_at';
    try {
        const result = await pool.query(query, [req.userId, content, mediaUrl, expiresAt]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating story' });
    }
});
// Recupera le storie degli utenti
app.get('/stories', authenticate, async (req, res) => {
    const query = `
        SELECT s.id, s.user_id, s.content, s.media_url, s.created_at, u.username
        FROM stories s
        JOIN users u ON s.user_id = u.id
        WHERE s.expires_at > NOW()
        ORDER BY s.created_at DESC
        LIMIT 20
    `;
    try {
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching stories' });
    }
});
// Endpoint per inviare un messaggio vocale
app.post('/voice-messages', authenticate, upload.single('audio'), async (req, res) => {
    const { receiverId } = req.body;
    const file = req.file;

    if (!file || !receiverId) {
        return res.status(400).json({ message: 'Audio file and receiver ID are required' });
    }

    // Verifica che l'utente non stia inviando un messaggio a se stesso
    if (req.userId === receiverId) {
        return res.status(400).json({ message: 'You cannot send a message to yourself' });
    }

    const audioUrl = await uploadToS3(file);

    const query = 'INSERT INTO voice_messages (sender_id, receiver_id, audio_url) VALUES ($1, $2, $3) RETURNING id, sender_id, receiver_id, audio_url, created_at';
    try {
        const result = await pool.query(query, [req.userId, receiverId, audioUrl]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error sending voice message' });
    }
});
// Funzione per caricare file audio su S3
const uploadToS3 = async (file) => {
    const AWS = require('aws-sdk');
    const s3 = new AWS.S3();
    const params = {
        Bucket: 'your-s3-bucket',
        Key: `${Date.now()}-${file.originalname}`,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'public-read',
    };

    try {
        const s3Response = await s3.upload(params).promise();
        return s3Response.Location;
    } catch (err) {
        throw new Error('Error uploading audio to S3');
    }
};
// Avvia una sessione di livestreaming
app.post('/livestream', authenticate, async (req, res) => {
    const { title, description } = req.body;

    if (!title || !description) {
        return res.status(400).json({ message: 'Title and description are required' });
    }

    const query = 'INSERT INTO livestreams (user_id, title, description) VALUES ($1, $2, $3) RETURNING id, title, description, created_at';
    try {
        const result = await pool.query(query, [req.userId, title, description]);
        // Restituire l'ID del livestream
        res.status(201).json({ message: 'Livestream started', streamId: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error starting livestream' });
    }
});
// Endpoint per connettersi a un livestream
app.get('/livestream/:streamId', authenticate, async (req, res) => {
    const { streamId } = req.params;

    // Recupera i dettagli del livestream
    const query = 'SELECT * FROM livestreams WHERE id = $1';
    const result = await pool.query(query, [streamId]);

    if (result.rows.length === 0) {
        return res.status(404).json({ message: 'Livestream not found' });
    }

    // Qui andrebbe la logica per connettere l'utente al livestream tramite WebRTC

    res.json({ message: 'Connected to livestream', streamId });
});const fetch = require('node-fetch');

// Funzione per filtrare il contenuto con Perspective API
async function checkOffensiveContent(text) {
    const response = await fetch('https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=YOUR_API_KEY', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            comment: { text },
            languages: ['en'],
            requestedAttributes: { TOXICITY: {} }
        })
    });

    const data = await response.json();
    return data.attributeScores.TOXICITY.summaryScore.value;
}

// Endpoint per creare un post con il controllo del contenuto
app.post('/posts', authenticate, async (req, res) => {
    const { content } = req.body;

    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    // Verifica se il contenuto è offensivo
    const toxicityScore = await checkOffensiveContent(content);
    if (toxicityScore > 0.7) { // Se il punteggio di tossicità è alto
        return res.status(400).json({ message: 'Your content contains offensive language' });
    }

    // Procedi con la creazione del post
    const query = 'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING id, content';
    try {
        const result = await pool.query(query, [req.userId, content]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating post' });
    }
});
CREATE TABLE user_reports (
    id SERIAL PRIMARY KEY,
    reporter_id INT REFERENCES users(id),
    reported_id INT REFERENCES users(id),
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_blocks (
    id SERIAL PRIMARY KEY,
    blocker_id INT REFERENCES users(id),
    blocked_id INT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Blocco di un utente
app.post('/block', authenticate, async (req, res) => {
    const { blockedUserId } = req.body;

    if (req.userId === blockedUserId) {
        return res.status(400).json({ message: 'You cannot block yourself' });
    }

    const query = 'INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, blockedUserId]);
        res.status(200).json({ message: 'User blocked successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error blocking user' });
    }
});

// Segnalazione di un utente
app.post('/report', authenticate, async (req, res) => {
    const { reportedUserId, reason } = req.body;

    if (req.userId === reportedUserId) {
        return res.status(400).json({ message: 'You cannot report yourself' });
    }

    const query = 'INSERT INTO user_reports (reporter_id, reported_id, reason) VALUES ($1, $2, $3)';
    try {
        await pool.query(query, [req.userId, reportedUserId, reason]);
        res.status(200).json({ message: 'User reported successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error reporting user' });
    }
});
CREATE TABLE post_interactions (
    id SERIAL PRIMARY KEY,
    post_id INT REFERENCES posts(id),
    user_id INT REFERENCES users(id),
    interaction_type TEXT,  -- 'like', 'comment', etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Registrare un'interazione con un post
app.post('/interactions', authenticate, async (req, res) => {
    const { postId, interactionType } = req.body;

    if (!postId || !interactionType) {
        return res.status(400).json({ message: 'Post ID and interaction type are required' });
    }

    const query = 'INSERT INTO post_interactions (post_id, user_id, interaction_type) VALUES ($1, $2, $3)';
    try {
        await pool.query(query, [postId, req.userId, interactionType]);
        res.status(200).json({ message: 'Interaction recorded' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error recording interaction' });
    }
});
// Recupera il numero di like di un post
app.get('/posts/:postId/likes', async (req, res) => {
    const { postId } = req.params;

    const query = `
        SELECT COUNT(*) AS like_count
        FROM post_interactions
        WHERE post_id = $1 AND interaction_type = 'like'
    `;
    try {
        const result = await pool.query(query, [postId]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching likes count' });
    }
});
ALTER TABLE posts ADD COLUMN visibility TEXT DEFAULT 'public';
// Modifica la visibilità di un post
app.put('/posts/:postId/visibility', authenticate, async (req, res) => {
    const { postId } = req.params;
    const { visibility } = req.body; // 'public', 'private', 'friends'

    if (!['public', 'private', 'friends'].includes(visibility)) {
        return res.status(400).json({ message: 'Invalid visibility' });
    }

    const query = 'UPDATE posts SET visibility = $1 WHERE id = $2 AND user_id = $3';
    try {
        await pool.query(query, [visibility, postId, req.userId]);
        res.status(200).json({ message: 'Post visibility updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating post visibility' });
    }
});
// Modifica le impostazioni di privacy dell'account
app.put('/settings/privacy', authenticate, async (req, res) => {
    const { allowMessagesFrom, allowFollowersFrom } = req.body;

    const query = 'UPDATE users SET allow_messages_from = $1, allow_followers_from = $2 WHERE id = $3';
    try {
        await pool.query(query, [allowMessagesFrom, allowFollowersFrom, req.userId]);
        res.status(200).json({ message: 'Privacy settings updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating privacy settings' });
    }
});
const fetch = require('node-fetch');

// Funzione per filtrare il contenuto con Perspective API
async function checkOffensiveContent(text) {
    const response = await fetch('https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=YOUR_API_KEY', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            comment: { text },
            languages: ['en'],
            requestedAttributes: { TOXICITY: {} }
        })
    });

    const data = await response.json();
    return data.attributeScores.TOXICITY.summaryScore.value;
}

// Endpoint per creare un post con il controllo del contenuto
app.post('/posts', authenticate, async (req, res) => {
    const { content } = req.body;

    if (!content) {
        return res.status(400).json({ message: 'Content is required' });
    }

    // Verifica se il contenuto è offensivo
    const toxicityScore = await checkOffensiveContent(content);
    if (toxicityScore > 0.7) { // Se il punteggio di tossicità è alto
        return res.status(400).json({ message: 'Your content contains offensive language' });
    }

    // Procedi con la creazione del post
    const query = 'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING id, content';
    try {
        const result = await pool.query(query, [req.userId, content]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating post' });
    }
});
CREATE TABLE user_reports (
    id SERIAL PRIMARY KEY,
    reporter_id INT REFERENCES users(id),
    reported_id INT REFERENCES users(id),
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_blocks (
    id SERIAL PRIMARY KEY,
    blocker_id INT REFERENCES users(id),
    blocked_id INT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Blocco di un utente
app.post('/block', authenticate, async (req, res) => {
    const { blockedUserId } = req.body;

    if (req.userId === blockedUserId) {
        return res.status(400).json({ message: 'You cannot block yourself' });
    }

    const query = 'INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2)';
    try {
        await pool.query(query, [req.userId, blockedUserId]);
        res.status(200).json({ message: 'User blocked successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error blocking user' });
    }
});
// Segnalazione di un utente
app.post('/report', authenticate, async (req, res) => {
    const { reportedUserId, reason } = req.body;

    if (req.userId === reportedUserId) {
        return res.status(400).json({ message: 'You cannot report yourself' });
    }

    const query = 'INSERT INTO user_reports (reporter_id, reported_id, reason) VALUES ($1, $2, $3)';
    try {
        await pool.query(query, [req.userId, reportedUserId, reason]);
        res.status(200).json({ message: 'User reported successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error reporting user' });
    }
});
CREATE TABLE post_interactions (
    id SERIAL PRIMARY KEY,
    post_id INT REFERENCES posts(id),
    user_id INT REFERENCES users(id),
    interaction_type TEXT,  -- 'like', 'comment', etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Registrare un'interazione con un post
app.post('/interactions', authenticate, async (req, res) => {
    const { postId, interactionType } = req.body;

    if (!postId || !interactionType) {
        return res.status(400).json({ message: 'Post ID and interaction type are required' });
    }

    const query = 'INSERT INTO post_interactions (post_id, user_id, interaction_type) VALUES ($1, $2, $3)';
    try {
        await pool.query(query, [postId, req.userId, interactionType]);
        res.status(200).json({ message: 'Interaction recorded' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error recording interaction' });
    }
});
// Recupera il numero di like di un post
app.get('/posts/:postId/likes', async (req, res) => {
    const { postId } = req.params;

    const query = `
        SELECT COUNT(*) AS like_count
        FROM post_interactions
        WHERE post_id = $1 AND interaction_type = 'like'
    `;
    try {
        const result = await pool.query(query, [postId]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching likes count' });
    }
});
ALTER TABLE posts ADD COLUMN visibility TEXT DEFAULT 'public';
// Modifica la visibilità di un post
app.put('/posts/:postId/visibility', authenticate, async (req, res) => {
    const { postId } = req.params;
    const { visibility } = req.body; // 'public', 'private', 'friends'

    if (!['public', 'private', 'friends'].includes(visibility)) {
        return res.status(400).json({ message: 'Invalid visibility' });
    }

    const query = 'UPDATE posts SET visibility = $1 WHERE id = $2 AND user_id = $3';
    try {
        await pool.query(query, [visibility, postId, req.userId]);
        res.status(200).json({ message: 'Post visibility updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating post visibility' });
    }
});
// Modifica le impostazioni di privacy dell'account
app.put('/settings/privacy', authenticate, async (req, res) => {
    const { allowMessagesFrom, allowFollowersFrom } = req.body;

    const query = 'UPDATE users SET allow_messages_from = $1, allow_followers_from = $2 WHERE id = $3';
    try {
        await pool.query(query, [allowMessagesFrom, allowFollowersFrom, req.userId]);
        res.status(200).json({ message: 'Privacy settings updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating privacy settings' });
    }
});
npm install firebase-admin
const admin = require('firebase-admin');

// Inizializzare Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.cert('path/to/your/firebase/credentials.json')
});

// Funzione per inviare una notifica push
const sendPushNotification = async (toToken, title, message) => {
    const messagePayload = {
        notification: {
            title: title,
            body: message,
        },
        token: toToken,
    };

    try {
        const response = await admin.messaging().send(messagePayload);
        console.log('Push notification sent successfully:', response);
    } catch (error) {
        console.error('Error sending push notification:', error);
    }
};

// Endpoint per inviare notifiche push
app.post('/send-notification', authenticate, async (req, res) => {
    const { userId, title, message } = req.body;

    const query = 'SELECT device_token FROM users WHERE id = $1';
    try {
        const result = await pool.query(query, [userId]);
        const deviceToken = result.rows[0]?.device_token;
        
        if (!deviceToken) {
            return res.status(400).json({ message: 'User does not have a device token' });
        }

        // Invia la notifica push
        await sendPushNotification(deviceToken, title, message);
        res.status(200).json({ message: 'Notification sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error sending notification' });
    }
});
// Endpoint per aggiornare il token del dispositivo dell'utente
app.post('/update-device-token', authenticate, async (req, res) => {
    const { deviceToken } = req.body;

    if (!deviceToken) {
        return res.status(400).json({ message: 'Device token is required' });
    }

    const query = 'UPDATE users SET device_token = $1 WHERE id = $2';
    try {
        await pool.query(query, [deviceToken, req.userId]);
        res.status(200).json({ message: 'Device token updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating device token' });
    }
});
-- Creare un indice full-text sui post
CREATE INDEX posts_search_index ON posts USING gin(to_tsvector('english', content));

-- Creare un indice full-text sugli utenti
CREATE INDEX users_search_index ON users USING gin(to_tsvector('english', username));
// Ricerca avanzata: Cerca post e utenti
app.get('/search', async (req, res) => {
    const { query } = req.query; // parola o frase da cercare

    if (!query) {
        return res.status(400).json({ message: 'Search query is required' });
    }

    const postsQuery = `
        SELECT id, content FROM posts
        WHERE to_tsvector('english', content) @@ to_tsquery('english', $1)
        ORDER BY created_at DESC
        LIMIT 10;
    `;
    
    const usersQuery = `
        SELECT id, username FROM users
        WHERE to_tsvector('english', username) @@ to_tsquery('english', $1)
        LIMIT 10;
    `;

    try {
        const postsResult = await pool.query(postsQuery, [query]);
        const usersResult = await pool.query(usersQuery, [query]);

        res.json({
            posts: postsResult.rows,
            users: usersResult.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error performing search' });
    }
});
// Aggiungi la paginazione alla ricerca
app.get('/search', async (req, res) => {
    const { query, page = 1, pageSize = 10 } = req.query; // Parola da cercare, pagina e dimensione pagina

    if (!query) {
        return res.status(400).json({ message: 'Search query is required' });
    }

    const offset = (page - 1) * pageSize;

    const postsQuery = `
        SELECT id, content FROM posts
        WHERE to_tsvector('english', content) @@ to_tsquery('english', $1)
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3;
    `;
    
    const usersQuery = `
        SELECT id, username FROM users
        WHERE to_tsvector('english', username) @@ to_tsquery('english', $1)
        LIMIT $2 OFFSET $3;
    `;

    try {
        const postsResult = await pool.query(postsQuery, [query, pageSize, offset]);
        const usersResult = await pool.query(usersQuery, [query, pageSize, offset]);

        res.json({
            posts: postsResult.rows,
            users: usersResult.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error performing search' });
    }
});
CREATE TABLE user_activity (
    user_id INT REFERENCES users(id),
    post_count INT DEFAULT 0,
    comment_count INT DEFAULT 0,
    like_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Funzione per aggiornare le statistiche dell'utente
const updateUserActivity = async (userId, activityType) => {
    const columnMap = {
        'post': 'post_count',
        'comment': 'comment_count',
        'like': 'like_count',
    };

    const column = columnMap[activityType];

    if (!column) return;

    const query = `
        INSERT INTO user_activity (user_id, ${column}) 
        VALUES ($1, 1)
        ON CONFLICT (user_id)
        DO UPDATE SET ${column} = ${column} + 1;
    `;
    
    await pool.query(query, [userId]);
};

// Aggiungi questa funzione dopo le interazioni
app.post('/interactions', authenticate, async (req, res) => {
    const { postId, interactionType } = req.body;

    if (!postId || !interactionType) {
        return res.status(400).json({ message: 'Post ID and interaction type are required' });
    }

    await updateUserActivity(req.userId, interactionType); // Aggiorna l'attività dell'utente

    const query = 'INSERT INTO post_interactions (post_id, user_id, interaction_type) VALUES ($1, $2, $3)';
    try {
        await pool.query(query, [postId, req.userId, interactionType]);
        res.status(200).json({ message: 'Interaction recorded' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error recording interaction' });
    }
});
// Recupera il leaderboard
app.get('/leaderboard', async (req, res) => {
    const query = `
        SELECT users.username, user_activity.post_count, user_activity.comment_count, user_activity.like_count
        FROM user_activity
        JOIN users ON user_activity.user_id = users.id
        ORDER BY user_activity.post_count DESC, user_activity.comment_count DESC, user_activity.like_count DESC
        LIMIT 10;
    `;
    
    try {
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching leaderboard' });
    }
});