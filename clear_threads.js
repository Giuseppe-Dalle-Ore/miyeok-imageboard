/* Import the SQLite3 module in verbose mode for better error messages */
const sqlite3 = require('sqlite3').verbose();

/* Connect to the SQLite database */
const db = new sqlite3.Database('./miyeok.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1); // Exit the process if there's an error
    }

    // Delete all posts from the 'posts' table
    db.run('DELETE FROM posts', (err) => {
        if (err) {
            console.error('Error deleting threads:', err);
            process.exit(1); // Exit the process if there's an error
        } else {
            console.log('All threads deleted successfully'); // Log success message
        }
        db.close(); // Close the database connection
    });
});