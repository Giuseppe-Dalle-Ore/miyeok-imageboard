/* Import the SQLite3 module in verbose mode for better error messages */
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

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
                        pinned BOOLEAN DEFAULT 0, -- Whether the thread is pinned (0 = false, 1 = true)
                        ip_address TEXT, -- IP address of the poster
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

                    // Check if 'pinned' column exists, and add it if not
                    db.all(`PRAGMA table_info(posts)`, (err, columns) => {
                        if (err) {
                            console.error('Error checking posts table schema:', err.message);
                            reject(err);
                            return;
                        }

                        const hasPinnedColumn = columns.some(col => col.name === 'pinned');
                        if (!hasPinnedColumn) {
                            db.run(`
                                ALTER TABLE posts ADD COLUMN pinned BOOLEAN DEFAULT 0
                            `, (err) => {
                                if (err) {
                                    console.error('Error adding pinned column:', err.message);
                                    reject(err);
                                    return;
                                }
                                console.log('Pinned column added to posts table');
                            });
                        } else {
                            console.log('Pinned column already exists');
                        }

                        // Check if 'ip_address' column exists, and add it if not
                        const hasIpAddressColumn = columns.some(col => col.name === 'ip_address');
                        if (!hasIpAddressColumn) {
                            db.run(`
                                ALTER TABLE posts ADD COLUMN ip_address TEXT
                            `, (err) => {
                                if (err) {
                                    console.error('Error adding ip_address column:', err.message);
                                    reject(err);
                                    return;
                                }
                                console.log('Ip_address column added to posts table');
                            });
                        } else {
                            console.log('Ip_address column already exists');
                        }
                    });

                    // Create the 'bans' table for banned IPs
                    db.run(`
                        CREATE TABLE IF NOT EXISTS bans (
                            ip_address TEXT PRIMARY KEY, -- IP address of the banned user
                            reason TEXT, -- Reason for the ban
                            banned_at DATETIME NOT NULL -- Timestamp of the ban
                        )
                    `, (err) => {
                        if (err) {
                            console.error('Error creating bans table:', err.message);
                            reject(err);
                            return;
                        }
                        console.log('Bans table created or already exists');
                    });

                    // Create the 'admins' table for admin credentials
                    db.run(`
                        CREATE TABLE IF NOT EXISTS admins (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL
                        )
                    `, (err) => {
                        if (err) {
                            console.error('Error creating admins table:', err.message);
                            reject(err);
                            return;
                        }
                        console.log('Admins table created or already exists');
                    });

                    // Create the 'boards' table for managing boards
                    db.run(`
                        CREATE TABLE IF NOT EXISTS boards (
                            name TEXT PRIMARY KEY, -- Board shorthand name (e.g., 'ish')
                            description TEXT NOT NULL, -- Board description
                            display_name TEXT NOT NULL -- Display name for the home page (e.g., 'random')
                        )
                    `, (err) => {
                        if (err) {
                            console.error('Error creating boards table:', err.message);
                            reject(err);
                            return;
                        }
                        console.log('Boards table created or already exists');

                        // Insert default boards if the table is empty
                        db.get(`SELECT COUNT(*) as count FROM boards`, (err, row) => {
                            if (err) {
                                console.error('Error checking boards table:', err.message);
                                reject(err);
                                return;
                            }

                            if (row.count === 0) {
                                const defaultBoards = [
                                    ['ish', 'General discussion and random topics.', 'random'],
                                    ['tech', 'Technology, gadgets, and software.', 'tech'],
                                    ['mu', 'Music, bands, and audio discussions.', 'music'],
                                    ['animals', 'All about pets, wildlife, and animal lovers.', 'animals'],
                                    ['2Afriendly', 'Second Amendment discussions and firearm topics.', '2Afriendly'],
                                    ['pictures', 'Share and discuss photos and images.', 'pictures'],
                                    ['videos', 'Video content, clips, and filmmaking.', 'videos']
                                ];

                                const stmt = db.prepare(`INSERT INTO boards (name, description, display_name) VALUES (?, ?, ?)`);
                                defaultBoards.forEach(board => {
                                    stmt.run(board, (err) => {
                                        if (err) {
                                            console.error(`Error inserting board ${board[0]}:`, err.message);
                                        }
                                    });
                                });
                                stmt.finalize((err) => {
                                    if (err) {
                                        console.error('Error finalizing board insertions:', err.message);
                                        reject(err);
                                        return;
                                    }
                                    console.log('Default boards inserted');
                                });
                            } else {
                                console.log('Boards table already contains data');
                            }
                        });

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

                        // Insert a default admin (username: 'admin', password: 'admin123') if not exists
                        const defaultUsername = 'admin';
                        const defaultPassword = 'admin123';
                        bcrypt.hash(defaultPassword, 10, (err, hashedPassword) => {
                            if (err) {
                                console.error('Error hashing default admin password:', err.message);
                                reject(err);
                                return;
                            }

                            db.run(`
                                INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)
                            `, [defaultUsername, hashedPassword], (err) => {
                                if (err) {
                                    console.error('Error inserting default admin:', err.message);
                                    reject(err);
                                    return;
                                }
                                console.log('Default admin created or already exists');
                            });
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
    });
};

/* Export the database initialization as a Promise */
module.exports = initializeDatabase();