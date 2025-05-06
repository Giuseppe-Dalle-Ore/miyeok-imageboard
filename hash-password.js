const bcrypt = require('bcrypt');

const newPassword = 'PutitInherbutt69420'; // Replace with your desired password

bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err);
        return;
    }
    console.log('Hashed Password:', hash);
});