// Imports
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const date = require('node-datetime');

const app = express();

// Reading Json
app.use(express.json());

// Import Model User
const User = require('./model/User');

// Home

app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Home' });
});

function checkToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split('')[1];

  if (!token) {
    return res.status(401).json({ msg: 'Não autorizado' });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    return res.status(400).json({ msg: 'Não autorizado' });
  }
}

// Private

app.get('/user/:id', checkToken, async (req, res) => {
  const { id } = req.params;
  const user = await User.findById(id, '-password');

  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado' });
  }

  return res.status(200).json({ user });
});

// Create User
app.post('/auth/register', async (req, res) => {
  const {
    name, email, password, confirmpassword, telefone,
  } = req.body;

  // Simple Validations

  if (!name) {
    return res.status(422).json({ msg: 'Campo Obrigatório' });
  }
  if (!email) {
    return res.status(422).json({ msg: 'Campo Obrigatório' });
  }
  if (!password) {
    return res.status(422).json({ msg: 'Campo Obrigatório' });
  }
  if (password !== confirmpassword) {
    return res.status(422).json({ msg: 'Senhas divergentes' });
  }
  if (!telefone) {
    return res.status(422).json({ msg: 'Campo Obrigatório' });
  }

  // Verifying if user exists in database

  const userExists = await User.findOne({ email });

  if (userExists) {
    return res.status(401).json({ msg: 'E-mail já existente' });
  }

  // Hash Password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const dt = date.create();
  const formatted = dt.format('Y-m-d H:M:S');

  const user = new User({
    name,
    email,
    password: passwordHash,
    telefone,
    data_criacao: formatted,
    data_atualizacao: formatted,
  });

  try {
    await user.save();

    return res
      .status(201)
      .json({ msg: 'Usuário cadastrado com sucesso', user });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ msg: 'Serviço Indisponível' });
  }
});

// Login User
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(422).json({ msg: 'Campo Obrigatório' });
  }
  if (!password) {
    return res.status(422).json({ msg: 'Campo Obrigatório' });
  }

  // Check if User Exists and password matches
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ msg: 'Usuário e/ou senha inválidos' });
  }

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(401).json({ msg: 'Usuário e/ou senha inválidos' });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret,
    );

    return res
      .status(200)
      .json({ msg: 'Autenticação realizada com sucesso', token });
  } catch (error) {
    console.log(error);

    return res.status(500).json({
      msg: 'Serviço Indisponível',
    });
  }
});

// User Database
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

// Connection in MongoDBAtlas
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.pxoilwy.mongodb.net/?retryWrites=true&w=majority`,
  )
  .then(() => {
    app.listen(3000);
    console.log('conectado');
  })
  .catch((err) => console.log(err));
