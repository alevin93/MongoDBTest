require('dotenv').config();
const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');
const corsOptions = require('./config/corsOptions');
const { logger, logEvents } = require('./middleware/logEvents');
const errorHandler = require('./middleware/errorHandler');
const verifyJWT = require('./middleware/verifyJWT');
const cookieParser = require('cookie-parser');
const credentials = require('./middleware/credentials');
const mongoose = require('mongoose');
const connectDB = require('./config/dbConn')
const PORT = process.env.PORT || 3000;

//connect to MongoDB
connectDB();

//custom middleware logger
app.use(logger)
//cross origin resource sharing
app.use(credentials);
app.use(cors(corsOptions));

app.use(express.urlencoded({ extended: false}));

app.use(express.json());

//middleware for cookies
app.use(cookieParser());

//routes
app.use('/', require('./routes/root'));
app.use('/register', require('./routes/register'));
app.use('/auth', require('./routes/auth'));
app.use('/refresh', require('./routes/refresh'));
app.use('/logout', require('./routes/logout'));

app.use(verifyJWT);
app.use('/employees', require('./routes/api/employees'));




app.all('/*', (req, res) => {
    res.status(404);
    
    if (req.accepts('html')) {
        res.sendFile(path.join(__dirname, 'views', '404.html'));
    }
    if (req.accepts('json')) {
        res.json({ error: "ERROR 404" });
    } else {
        res.type('txt').send("ERROR 404");
    }
})

app.use(errorHandler);

mongoose.connection.once('open', () => {
    console.log("Connected to MongoDB");
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});