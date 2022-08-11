const mongoose = require('mongoose');

const User = mongoose.model('User', {
  name: String,
  email: String,
  password: String,
  telefone: [{ numero: String, ddd: String }],
  data_criacao: String,
  data_atualizacao: String,
  token: String,
  ultimo_login: String,
});

module.exports = User;
