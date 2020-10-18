const express = require('express')
const app = express()

const jwt = require('jsonwebtoken')

app.use(express.json())

app.get('/', (req, res) => {
  res.send('Hello')
})

app.post('/login', (req, res) => {
  // authenticate user

  // create and send jsonwebtoken
})

app.post('/logout', (req, res) => {
  // logout
})

app.listen(3000)