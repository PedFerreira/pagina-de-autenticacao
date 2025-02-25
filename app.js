//initialSetup
require('dotenv').config()
const express = require('express')
const bcrypt = require('bcrypt')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const User = require('./models/User')
const port = 3000
const app = express()


//getCredentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
const acessTokenDB = `mongodb+srv://${dbUser}:${dbPassword}@projetopensao.rdt0y.mongodb.net/?retryWrites=true&w=majority&appName=ProjetoPensao`

//setConection
mongoose
    .connect(acessTokenDB)
    .then( () => app.listen(port))
    .catch((err) => console.log('erro ao conectar ao banco de dados: -- ', err)) 

function checkToken(req, res, next) {
    const headerParams = req.headers['authorization']
    const token = headerParams && headerParams.split(' ')[1]

    if(!token)
        return res.status(401).json({msg: 'Acesso negado!'})

    try {
        
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()

    } catch (error) {
        return res.status(400).json({msg : 'Token invalido!'})
    }
}

app.use(express.json())

//setRoutes - publicRoute
app.get('/', (req, res) =>{
    res.status(200).json({msg: 'Bem vindo e funcionou'})
})

//setRoutes - PrivateRoute :userId

app.get('/users/:id', checkToken, async (req, res) =>{

    const id = req.params.id
    const userFound = await User.findById(id, '-password')
    
    if(!userFound){
        return res.status(404).json({msg : 'Usuario nao encontrado'})
    }
    else{
        return res.status(200).json({userFound})
    }
    
})

//setRoutes - register User
app.post('/auth/register', async (req, res) => {
    
    const {name, email, password, confirmPassword} = req.body

    if(!name){
        return res.status(422).json({msg : 'O nome é obrigatório.'})
    }
    if(!email){
        return res.status(422).json({msg : 'O email é obrigatório.'})
    }
    if(!password){
        return res.status(422).json({msg : 'A senha é obrigatório.'})
    }
    if(password !== confirmPassword){
        return res.status(422).json({msg : 'A senhas não conferem.'})
    }

    const userExist = await User.findOne({email: email})
    console.log(userExist)
    if(userExist){
        return res.status(422).json({msg: `Usuário já cadastrado: ${email}`})
    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const newUser = new User({
        name, email, password: passwordHash
    })

    try {
        await newUser.save()
        return res.status(201).json({msg: 'Registro criado com sucesso'})

    } catch (error) {
        return res.status(500).json({msg: 'Erro no servidor'})
    }

})

//setRoutes - login User
app.post('/auth/login', async (req, res) => {
    
    const {email, password} = req.body

    if(!email){
        return res.status(422).json({msg: 'Insira um email para continuar'})
    }
    if(!password){
        return res.status(422).json({msg: 'Insira sua senha'})
    }

    const userExist = await User.findOne({email: email})
    if(!userExist){
        return res.status(404).json({msg: 'Usuário não encontrado!!'})
    }

    const matchPass = await bcrypt.compare(password, userExist.password)
    if(!matchPass){
        return res.status(422).json({msg: 'Senha inválida'})
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({ id: userExist._id }, secret)

        return res.status(200).json({msg: 'Autenticacao realizada com Sucesso! Token: ', token})

    } catch (error) {
        return res.status(500).json({msg: 'Erro no servidor'})
    }
})