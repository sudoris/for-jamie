require('dotenv').config()

const express = require('express')
const app = express()
const cors = require('cors')
const bcrypt = require('bcrypt')
const axios = require('axios')

const jwt = require('jsonwebtoken')

app.use(express.json())
// allow * for dev
app.use(cors())

const users = []

app.get('/', (req, res) => {
  return res.send(users)
})

app.post('/test', (req, res) => {
  return res.send('ok')
})

app.post('/signup', async (req, res) => {  
  if (!req.body.signupEmail || !req.body.signupPassword) {
    return res.sendStatus(422)
  }

  if (users.find(user => user.email === req.body.signupEmail)) {
    return res.sendStatus(409)
  }

  const user = { 
    email: req.body.signupEmail,
    password: req.body.signupPassword,
    firstname: req.body.signupFname,
    lastname: req.body.signupLname,
    gender: req.body.signupGender,
    birthday: req.body.signupBday,
    schoolname: req.body.signupSchoolName,
    schooltype: req.body.signupSchoolType   
  }  
  
  try {
    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(user.password, salt)
    user.password = hashedPassword   
    
    // create user
    users.push(user)    

    // log in automatically for user after successful signup
    // note: must use unsalted password for log in
    const accessToken = await login({
      email: user.email,
      password: req.body.signupPassword
    })

    return res.send({ accessToken })
  } catch (err) {
    return res.sendStatus(500)
  } 
})

app.post('/login', async (req, res) => { 
  await login({ email: req.body.email, password: req.body.password })  
    .then((accessToken) => res.send({ accessToken }))
    .catch(err => res.sendStatus(400)) 
})

app.delete('/logout', (req, res) => {
  
})

app.get('/enrolled', authenticateToken, (req, res) => {
  return res.send(['Math', 'Science', 'English'])
})

// middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  // token comes after 'Bearer '
  const token = authHeader && authHeader.split(' ')[1] 
  if (!token) {
    return res.sendStatus(401)
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {      
      return res.sendStatus(403)
    }
    req.user = user
    next()
  })
}

// helper functions
async function login({ email, password }) {
  const user = users.find(user => user.email === email )
  if (!user) {
    throw new Error('user not found')
  }

  // authenticate user
  try {
    if (await bcrypt.compare(password, user.password)) {
      // create and send jsonwebtoken
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
      return accessToken
    } else {
      throw new Error('wrong password')
    }
  } catch (err) {
    throw err
  }
}

app.listen(3333)