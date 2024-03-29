const jwt = require('jsonwebtoken')
const JWT_Secret = "goodboy"

//middleware
const fetchuser = (req, res, next)=>{
    let token = req.header('auth-token')
    if(!token){
        res.status(401).send({error:"login required"})
    }
    try {
        let data = jwt.verify(token, JWT_Secret)
        req.user = data.findUser
        next()
    } catch (error) {
        res.status(401).json({error:"Wrong token"})
    }
}


module.exports = fetchuser