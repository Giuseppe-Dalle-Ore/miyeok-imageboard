/* Import the SQLite3 module in verbose mode for better error messages */
const sqlite3 = require('sqlite3').verbose();

/* Connect to the SQLite database */
const db = new sqlite3.Database('./miyeok.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1); // Exit the process if there's an error
    }

    console.log('Connected to SQLite database');

    // Add the thumbnail column to the posts table
    db.run(`
        ALTER TABLE posts ADD COLUMN thumbnail TEXT
    `, (err) => {
        if (err) {
            console.error('Error adding thumbnail column:', err.message);
            process.exit(1);
        }
        console.log('Thumbnail column added successfully');
        db.close();
    });
});