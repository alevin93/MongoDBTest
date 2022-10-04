const allowedOrigins = [

    'https://www.<yoursite>.com', 
    'http://127.0.0.1:5500', 
    'http://localhost:3000'

]; // This is to whitelist your own website so other cannot hit your backend

module.exports = allowedOrigins;