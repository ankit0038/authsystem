const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
        console.log(req.cookies);
        const token =  req.cookies.token || req.body.token || req.header('Authorization').replace('Bearer ', '');   //the token will come in headers  (Authorization header) of request and will always come in this format 'Bearer <token>'

        if(!token){
                return res.status(403).send("authorization token is miising");
        }

        try {
                const decode = jwt.verify(token, process.env.SECRET_KEY);
                console.log(decode);
        } catch (error) {
                return res.status(401).send("Invalid token");
        }
        return next();
}

module.exports = auth;