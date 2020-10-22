const express = require('express')
const app = express()
const bcrypt = require('bcrypt')

const jwt = require('jsonwebtoken')

app.use(express.json())

const users = []

app.get('/', (req, res) => {
  res.send('Hello')
})

app.post('/signup', async (req, res) => {  
  const user = { username: req.body.username, password: req.body.password }

  if (!user.username || !user.password) {
    res.status(422).send()
  }
  
  try {
    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(user.password, salt)
    user.password = hashedPassword

    // create user
    users.push(user)
    res.status(201).send()
  } catch {
    res.status(500).send()
  } 
})

app.post('/login', async (req, res) => {
  // check that user exists
  const user = users.find(user => user.username === req.body.username)
  if (!user) {
    return res.status(400).send('login failed')
  }

  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      res.send('Sucess')
    } else {
      res.send('login failed')
    }
  } catch {
    res.status(500).send()
  }

  // create and send jsonwebtoken
})

app.post('/logout', (req, res) => {
  // logout
})

app.listen(3333)