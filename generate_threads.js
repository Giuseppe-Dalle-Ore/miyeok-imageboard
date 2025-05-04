/* Import the SQLite3 module in verbose mode for better error messages */
const initializeDatabase = require('./database'); // Import the database initialization function

/* Initialize the database and then proceed with thread generation */
initializeDatabase.then((db) => {
    console.log('Connected to SQLite database');

    // Ensure database commands run sequentially
    db.serialize(() => {
        // First, clear existing threads to start fresh
        db.run('DELETE FROM posts', (err) => {
            if (err) {
                console.error('Error clearing existing threads:', err.message);
                process.exit(1);
            }
            console.log('Cleared existing threads');

            // Insert 3 threads into the 'ish' board
            const board = 'ish';
            const threadCount = 3; // We'll create 3 threads for this test
            let completedThreads = 0;

            for (let i = 1; i <= threadCount; i++) {
                const content = `Test thread #${i} content`;
                const timestamp = `2025-05-01 12:${String(i).padStart(2, '0')}:00`;

                db.run(`
                    INSERT INTO posts (board, content, image, parent_id, quote_id, tags, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [board, content, null, null, null, `tag${i}`, timestamp], function(err) {
                    if (err) {
                        console.error(`Error inserting thread #${i}:`, err.message);
                        process.exit(1);
                    }
                    const threadId = this.lastID;
                    console.log(`Inserted thread #${i} with ID ${threadId}`);

                    // Add replies to each thread
                    let replyCount;
                    if (i === 1) {
                        // Thread #1 will have 300 replies to hit the bump limit
                        replyCount = 300;
                    } else {
                        // Other threads will have fewer replies
                        replyCount = i * 10; // Thread #2: 20 replies, Thread #3: 30 replies
                    }
                    let completedReplies = 0;

                    if (replyCount === 0) {
                        completedThreads++;
                        checkCompletion();
                        return;
                    }

                    for (let j = 1; j <= replyCount; j++) {
                        const replyContent = `Reply #${j} to thread #${i}`;
                        const replyTimestamp = `2025-05-01 12:${String(i + j).padStart(2, '0')}:00`;
                        db.run(`
                            INSERT INTO posts (board, content, image, parent_id, quote_id, tags, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        `, [board, replyContent, null, threadId, null, null, replyTimestamp], (err) => {
                            if (err) {
                                console.error(`Error inserting reply #${j} to thread #${i}:`, err.message);
                                process.exit(1);
                            }
                            completedReplies++;
                            console.log(`Inserted reply #${j} to thread #${i}`);

                            if (completedReplies === replyCount) {
                                completedThreads++;
                                checkCompletion();
                            }
                        });
                    }
                });
            }

            // Function to check if all threads and replies are inserted
            function checkCompletion() {
                if (completedThreads === threadCount) {
                    db.get(`
                        SELECT COUNT(*) as total_threads
                        FROM posts
                        WHERE board = ? AND parent_id IS NULL
                    `, [board], (err, result) => {
                        if (err) {
                            console.error('Error counting threads:', err.message);
                            process.exit(1);
                        }
                        console.log(`Total threads in /${board} after insertion: ${result.total_threads}`);

                        db.get(`
                            SELECT COUNT(*) as total_replies
                            FROM posts
                            WHERE board = ? AND parent_id IS NOT NULL
                        `, [board], (err, result) => {
                            if (err) {
                                console.error('Error counting replies:', err.message);
                                process.exit(1);
                            }
                            console.log(`Total replies in /${board} after insertion: ${result.total_replies}`);

                            db.close((err) => {
                                if (err) {
                                    console.error('Error closing database:', err.message);
                                    process.exit(1);
                                }
                                console.log('Database connection closed');
                            });
                        });
                    });
                }
            }
        });
    });
}).catch((err) => {
    console.error('Failed to initialize database:', err.message);
    process.exit(1); // Exit the process if database initialization fails
});