const express = require("express")
const mongoose = require("mongoose")
const { validationResult, body } = require('express-validator');
const bcrypt = require("bcryptjs")
const jwt = require('jsonwebtoken')
const fetchuser = require('./middleware/fetchuser')
var cors = require('cors') 

const JWT_Secret = "goodboy"
const app = express()
const port = process.env.PORT || 8000
const URL = "mongodb://127.0.0.1:27017/dbname"
app.use(cors())
app.use(express.json())

function dbconnect(){
    mongoose.connect(URL).then(()=>{console.log("connected");}).catch((err)=>{console.log(err.message);})
}

dbconnect();

// user model
const uSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
},{versionKey:false})
const User = new mongoose.model("Collection",uSchema)

//notes model
const nSchema = new mongoose.Schema({
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref:'Collection'
    },
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    tag: {
        type: String,
        default: "General"
    },
    date: {
        type: Date,
        default: Date.now
    },
},{versionKey:false})
const Note = new mongoose.model("Cnote",nSchema)

//creating auth 
app.post("/api/auth/createuser",[
    body('email', 'Enter a valid email').isEmail(),
    body('name', 'Enter a valid name').isLength({min:3}),
    body('password', 'Password must be atleast 5 characters').isLength({min:5}),
], async function(req, res){
    let success =false
    const {name, email, password} = req.body
    const errors = validationResult(req)
    if (!errors.isEmpty()){
        return res.status(400).json({success,errors:errors.array()})
    }else{
        try {
            const mail = await
            User.findOne({email:email})
            
            if(mail){
                res.status(403).send({success,message:"User already registered, Please login!"})
            }
            else{
                const salt = await bcrypt.genSalt(10)
                const secPassword = await bcrypt.hash(password,salt)

                const create = new User({
                    name: name,
                    email: email,
                    password: secPassword
                })
                create.save();

                const data={
                    create:{
                        id: create.id
                    }
                }
                const authtoken = jwt.sign(data, JWT_Secret)

                if(!create){
                    res.status(403).send({message:"Cannot register try again after some time!"})
                }else{
                    success=true
                    res.status(200).json({success,authtoken})
                }
            }
        } catch (err) {
            if(err){
                res.status(403).send(err)
            }
        }
    }
})

//for login
app.post("/api/auth/login",[
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password cannot be blank').exists()
], async function(req, res){
    
    let success =false
    const {email, password} = req.body
    const errors = validationResult(req)
    if (!errors.isEmpty()){
        return res.status(400).json({errors:errors.array()})
    }
    
    try {
        const findUser = await
        User.findOne({email:email})

        if(!findUser){
            success=false
           return res.status(400).json({error:"Wrong Email"})
        }

        const passCompare = await bcrypt.compare(password, findUser.password)
        if(!passCompare){
            success=false
            return res.status(400).json({success,error:"Wrong credentials"})
        }

        const payload={
            findUser:{
                id: findUser.id
            }
        }
        const authtoken = jwt.sign(payload, JWT_Secret)
        success=true
        res.status(200).json({success,authtoken})

    } catch (error) {
        console.error(error.message);
        res.status(500).send({message:"Some error occured"})
    }

})

//get loggedin user details by verifying through fetchuser if it is the same user or not
app.post("/api/auth/getuser",fetchuser,async function(req, res){
    try {
        userId = req.user.id
        const findID = await User.findById(userId).select("-password")
        res.send(findID)
    } catch (error) {
        console.error(error.message);
        res.status(500).send({message:"Some error occured"})
    }
})

//get notes - login required
app.get('/api/notes/fetchnotes', fetchuser, async function(req,res){
    try {
        const notes = await Note.find({user:req.user.id})
    res.json(notes)
    } catch (error) {
        console.error(error.message);
        res.status(500).send({message:"Some error occured"})
    }
})
//add notes-login required
app.post('/api/notes/addnote', fetchuser,[
    body('title', 'Enter a valid title').isLength({min:3}),
    body('description', 'Description must be atleast 5 characters').isLength({min:5}),
],async function(req,res){
    try {
        const {title, description,tag} = req.body
        const errors = validationResult(req)
        if (!errors.isEmpty()){
            return res.status(400).json({errors:errors.array()})
        }
        const note = new Note({
            title,description,tag,user:req.user.id
        })
        const sNote = await note.save()
        res.json(sNote)
    }catch (error) {
        console.error(error.message);
        res.status(500).send({message:"Some error occured"})
    }
})
//update note-login required
app.put('/api/notes/updatenote/:id', fetchuser, async function(req,res){
    try {
        const {title, description,tag} = req.body
        const newNote = {};
        if (title){newNote.title = title}
        if (description){newNote.description = description}
        if (tag){newNote.tag = tag}
        //find note to update and update it
        let note = await Note.findById(req.params.id)
        if(!note){return res.status(404).send("Not found")}
        if(note.user.toString()!==req.user.id){
            return res.status(401).send("Not allowed")
        }
        note = await Note.findByIdAndUpdate(req.params.id,{$set: newNote},{new:true})
        res.json({note})
    } catch (error) {
        console.error(error.message);
        res.status(500).send({message:"Some error occured"})
    }
})
//delete note - login required
app.delete('/api/notes/deletenote/:id', fetchuser, async function(req,res){
    try {
        //find note to delete and delete it
        let note = await Note.findById(req.params.id)
        if(!note){return res.status(404).send("Not found")}
        //check if user owns this note
        if(note.user.toString()!==req.user.id){
            return res.status(401).send("Not allowed")
        }
        note = await Note.findByIdAndDelete(req.params.id)
        res.json({Success:"Note deleted", note:note})
    } catch (error) {
        console.error(error.message);
        res.status(500).send({message:"Some error occured"})
    }
    
})



app.listen(port,function(){
    console.log(`iNotes backend listening at http://localhost:${port}`)
})
