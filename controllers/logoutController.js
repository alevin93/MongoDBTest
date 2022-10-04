const User = require('../model/User');
const { resolveAny } = require('dns');

const handleLogout = async (req,res) => {
    //on client, also delete access token

    const cookies = req.cookies;
    if ( !cookies?.jwt ) return res.sendStatus(204); //no content to send back
    const refreshToken = cookies.jwt;

    // Is refresh token in db?
    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) { 
        res.clearCookie('jwt', { httpOnly: true, maxAge: 24 * 60 * 60 * 1000});
        return res.sendStatus(204); 
    }
    
    //delete refresh token from db
    foundUser.refreshToken = '';
    const result = await foundUser.save();
    console.log(result);

    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true}); // secure: true - only serve on https
    res.sendStatus(204);
}

module.exports = { handleLogout };