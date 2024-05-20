const mongoose = require('mongoose');

const TempUserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    username: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
    },
    passphrase: {
        type: String,
        required: true,
    },
});

module.exports = mongoose.model('TempUser', TempUserSchema);
