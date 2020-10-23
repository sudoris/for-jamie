require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')

const jwt = require('jsonwebtoken')

app.use(express.json())

const users = []

app.get('/', (req, res) => {
  return res.send(users)
})

app.post('/signup', async (req, res) => {  
  if (!req.body.username || !req.body.password) {
    return res.sendStatus(422)
  }

  const user = { 
    username: req.body.username,
    password: req.body.password,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    gender: req.body.gender,
    birthday: req.body.birthday,
    school: req.body.school,
    grade: req.body.grade    
  }  
  
  try {
    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(user.password, salt)
    user.password = hashedPassword

    // create user
    users.push(user)
    return res.sendStatus(201)
  } catch {
    return res.sendStatus(500)
  } 
})

app.post('/login', async (req, res) => {
  // check that user exists
  const user = users.find(user => user.username === req.body.username)
  if (!user) {
    return res.sendStatus(422)
  }

  // authenticate user
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // create and send jsonwebtoken
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h'})
      return res.send({ accessToken })
    } else {
      return res.sendStatus(403)
    }
  } catch {

    
    return res.sendStatus(500)
  }  
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
      console.log(new Date().toISOString())
      console.log(err)
      return res.sendStatus(403)
    }
    req.user = user
    next()
  })
}

app.listen(3333)