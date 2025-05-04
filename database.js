/* Import the SQLite3 module in verbose mode for better error messages */
const sqlite3 = require('sqlite3').verbose();

/* Function to initialize the SQLite database and return a Promise */
const initializeDatabase = () => {
    return new Promise((resolve, reject) => {
        // Create or connect to the SQLite database file 'miyeok.db'
        const db = new sqlite3.Database('./miyeok.db', (err) => {
            if (err) {
                console.error('Error opening database:', err.message);
                reject(err); // Reject the Promise if there's an error
                return;
            }
            console.log('Connected to SQLite database');

            // Ensure database commands run sequentially
            db.serialize(() => {
                // Create the 'posts' table if it doesn't already exist
                db.run(`
                    CREATE TABLE IF NOT EXISTS posts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, -- Auto-incrementing post ID
                        board TEXT NOT NULL, -- Board name (e.g., 'ish', 'tech')
                        content TEXT NOT NULL, -- Post content
                        image TEXT, -- Path to uploaded media (if any)
                        thumbnail TEXT, -- Path to video thumbnail (if video)
                        parent_id INTEGER, -- ID of the parent post (for replies, null for threads)
                        quote_id INTEGER, -- ID of the quoted post (if any)
                        tags TEXT, -- Tags for the thread (comma-separated, only for threads)
                        created_at DATETIME NOT NULL, -- Timestamp of when the post was created
                        FOREIGN KEY (parent_id) REFERENCES posts(id), -- Foreign key for parent_id
                        FOREIGN KEY (quote_id) REFERENCES posts(id) -- Foreign key for quote_id
                    )
                `, (err) => {
                    if (err) {
                        console.error('Error creating posts table:', err.message);
                        reject(err); // Reject the Promise if there's an error
                        return;
                    }
                    console.log('Posts table created or already exists');

                    // Create indexes on frequently queried columns
                    db.run(`
                        CREATE INDEX IF NOT EXISTS idx_board_parent ON posts (board, parent_id)
                    `, (err) => {
                        if (err) {
                            console.error('Error creating idx_board_parent index:', err.message);
                            reject(err);
                            return;
                        }
                        console.log('Index idx_board_parent created or already exists');
                    });

                    db.run(`
                        CREATE INDEX IF NOT EXISTS idx_created_at ON posts (created_at)
                    `, (err) => {
                        if (err) {
                            console.error('Error creating idx_created_at index:', err.message);
                            reject(err);
                            return;
                        }
                        console.log('Index idx_created_at created or already exists');
                    });

                    // Verify that the 'posts' table exists in the database
                    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='posts'", (err, row) => {
                        if (err) {
                            console.error('Error verifying posts table:', err.message);
                            reject(err); // Reject the Promise if there's an error
                            return;
                        }
                        if (!row) {
                            console.error('Posts table was not created');
                            reject(new Error('Posts table was not created')); // Reject if the table wasn't created
                            return;
                        }
                        console.log('Posts table verified');
                        resolve(db); // Resolve the Promise with the database connection
                    });
                });
            });
        });
    });
};

/* Export the database initialization as a Promise */
module.exports = initializeDatabase();