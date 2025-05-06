/* Import required Node.js modules */
const express = require('express');
const multer = require('multer');
const path = require('path');
const ffmpeg = require('fluent-ffmpeg');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const bcrypt = require('bcrypt');
const initializeDatabase = require('./database');

/* Initialize Express app */
const app = express();

// Enable trust proxy to handle X-Forwarded-For headers from Ngrok
app.set('trust proxy', 1);

// Explicitly set the views directory
app.set('views', path.join(__dirname, 'views'));

/* Set paths for ffmpeg and ffprobe binaries (used for video validation) */
ffmpeg.setFfmpegPath('C:\\Users\\gdall\\Documents\\ffmpeg-7.1.1-full_build\\ffmpeg-7.1.1-full_build\\bin\\ffmpeg.exe');
ffmpeg.setFfprobePath('C:\\Users\\gdall\\Documents\\ffmpeg-7.1.1-full_build\\ffmpeg-7.1.1-full_build\\bin\\ffprobe.exe');

/* Configure Express session middleware */
app.use(session({
    secret: 'miyeok-secret-key', // Replace with a secure key in production
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

/* Configure Multer for file uploads */
const storage = multer.diskStorage({
    destination: './public/uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

/* Define a file filter for Multer to restrict file types */
const fileFilter = (req, file, cb) => {
    const allowedImageTypes = /jpeg|jpg|png|gif/;
    const allowedVideoTypes = /mp4|webm/;
    const extname = allowedImageTypes.test(path.extname(file.originalname).toLowerCase()) ||
                   allowedVideoTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedImageTypes.test(file.mimetype) || allowedVideoTypes.test(file.mimetype);

    if (extname && mimetype) {
        cb(null, true);
    } else {
        cb(new Error('Only images (JPEG, PNG, GIF) and videos (MP4, WebM) are allowed'));
    }
};

/* Configure Multer with storage, file filter, and size limits */
const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB
    }
}).single('media');

/* Set up Express middleware */
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.static(__dirname)); // Serve files from the root directory
app.set('view engine', 'ejs');

/* Define available boards (categories) for the imageboard */
const boards = ['ish', 'tech', 'mu', 'animals', '2Afriendly', 'pictures', 'videos'];
const THREADS_PER_PAGE = 10;
const MAX_PAGES = 10;
const MAX_THREADS = THREADS_PER_PAGE * MAX_PAGES;
const BUMP_LIMIT = 300;

/* Middleware to check if the user is banned */
const checkBan = (req, res, next) => {
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    initializeDatabase.then((db) => {
        db.get(`SELECT * FROM bans WHERE ip_address = ?`, [userIp], (err, ban) => {
            if (err) {
                console.error('Error checking ban:', err);
                return res.status(500).render('error', {
                    status: 500,
                    message: 'An error occurred while checking ban status.',
                    boards
                });
            }
            if (ban) {
                return res.status(403).render('error', {
                    status: 403,
                    message: `You are banned. Reason: ${ban.reason}`,
                    boards
                });
            }
            next();
        });
    }).catch((err) => {
        console.error('Database error in checkBan:', err);
        res.status(500).render('error', {
            status: 500,
            message: 'Database error occurred.',
            boards
        });
    });
};

/* Middleware to check if the user is an admin */
const isAdmin = (req, res, next) => {
    if (req.session.isAdmin) {
        next();
    } else {
        res.redirect('/admin/login');
    }
};

/* Apply the checkBan middleware to all routes */
app.use(checkBan);

/* Configure rate limiting for the POST route */
const postLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 40, // Limit each IP to 40 posts per minute
    message: (req, res) => {
        res.status(429).render('error', {
            status: 429,
            message: 'You are posting too quickly! Please wait a minute before trying again.',
            boards
        });
    },
    standardHeaders: true,
    legacyHeaders: false,
});

/* Function to validate image files */
const validateImage = (filePath) => {
    return new Promise((resolve, reject) => {
        // No size limit for images; just resolve to allow the upload
        resolve();
    });
};

/* Function to validate video metadata (duration and resolution) */
const validateVideo = (filePath) => {
    return new Promise((resolve, reject) => {
        ffmpeg.ffprobe(filePath, (err, metadata) => {
            if (err) {
                return reject(new Error('Error processing video: ' + err.message));
            }

            const duration = metadata.format.duration;
            const streams = metadata.streams;
            const videoStream = streams.find(stream => stream.codec_type === 'video');

            if (!videoStream) {
                return reject(new Error('No video stream found'));
            }

            const width = videoStream.width;
            const height = videoStream.height;

            if (duration > 600) {
                return reject(new Error('Video duration exceeds 10 minutes'));
            }

            if (width > 3840 || height > 2160) {
                return reject(new Error('Video resolution exceeds 4K (3840x2160)'));
            }

            resolve();
        });
    });
};

/* Function to generate a thumbnail for a video */
const generateThumbnail = (videoPath) => {
    return new Promise((resolve, reject) => {
        const thumbnailPath = videoPath.replace(path.extname(videoPath), '_thumb.jpg');
        ffmpeg(videoPath)
            .screenshots({
                count: 1,
                folder: path.dirname(videoPath),
                filename: path.basename(thumbnailPath),
                size: '200x?'
            })
            .on('end', () => {
                resolve(`/uploads/${path.basename(thumbnailPath)}`);
            })
            .on('error', (err) => {
                reject(new Error('Error generating thumbnail: ' + err.message));
            });
    });
};

/* Function to convert text with markup and URLs to HTML */
const convertTextToHtml = (text) => {
    let processedText = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/(?<!\*)\*(.*?)\*(?!\*)/g, '<em>$1</em>')
        .replace(/^>\s(.*)$/gm, '<blockquote>$1</blockquote>');

    const urlRegex = /(\b(https?|ftp):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])|(\b(www\.)?[-A-Z0-9+&@#\/%?=~_|!:,.;]*\.[A-Z]{2,}(\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*)?\b)/gi;
    processedText = processedText.replace(urlRegex, (url) => {
        const href = url.match(/^(https?|ftp):\/\//i) ? url : `https://${url}`;
        return `<a href="${href}" target="_blank" rel="noopener noreferrer">${url}</a>`;
    });

    return sanitizeHtml(processedText, {
        allowedTags: ['a', 'strong', 'em', 'blockquote'],
        allowedAttributes: {
            a: ['href', 'target', 'rel']
        },
        allowedSchemes: ['http', 'https', 'ftp']
    });
};

/* Start the server after database initialization */
initializeDatabase.then((db) => {
    /* Route for the admin login page */
    app.get('/admin/login', (req, res) => {
        res.render('admin_login', { boards, error: null });
    });

    /* Route to handle admin login form submission */
    app.post('/admin/login', (req, res) => {
        const { username, password } = req.body;

        db.get(`SELECT * FROM admins WHERE username = ?`, [username], (err, admin) => {
            if (err) {
                console.error('Error fetching admin:', err);
                return res.status(500).render('admin_login', {
                    boards,
                    error: 'An error occurred. Please try again later.'
                });
            }

            if (!admin) {
                return res.render('admin_login', {
                    boards,
                    error: 'Invalid username or password.'
                });
            }

            bcrypt.compare(password, admin.password, (err, match) => {
                if (err) {
                    console.error('Error comparing passwords:', err);
                    return res.status(500).render('admin_login', {
                        boards,
                        error: 'An error occurred. Please try again later.'
                    });
                }

                if (match) {
                    req.session.isAdmin = true;
                    res.redirect('/');
                } else {
                    res.render('admin_login', {
                        boards,
                        error: 'Invalid username or password.'
                    });
                }
            });
        });
    });

    /* Route to log out */
    app.get('/admin/logout', (req, res) => {
        req.session.destroy((err) => {
            if (err) {
                console.error('Error logging out:', err);
                return res.status(500).render('error', {
                    status: 500,
                    message: 'Error logging out.',
                    boards
                });
            }
            res.redirect('/');
        });
    });

    /* Route for the admin change password page */
    app.get('/admin/change-password', isAdmin, (req, res) => {
        res.render('admin_change_password', { boards, error: null, success: null });
    });

    /* Route to handle admin change password form submission */
    app.post('/admin/change-password', isAdmin, (req, res) => {
        const { currentPassword, newPassword, confirmNewPassword } = req.body;

        // Validate inputs
        if (!currentPassword || !newPassword || !confirmNewPassword) {
            return res.render('admin_change_password', {
                boards,
                error: 'All fields are required.',
                success: null
            });
        }

        if (newPassword !== confirmNewPassword) {
            return res.render('admin_change_password', {
                boards,
                error: 'New passwords do not match.',
                success: null
            });
        }

        if (newPassword.length < 8) {
            return res.render('admin_change_password', {
                boards,
                error: 'New password must be at least 8 characters long.',
                success: null
            });
        }

        // Fetch the admin user (we'll use the first admin since there's only one for now)
        db.get(`SELECT * FROM admins LIMIT 1`, (err, admin) => {
            if (err || !admin) {
                console.error('Error fetching admin for password change:', err);
                return res.status(500).render('admin_change_password', {
                    boards,
                    error: 'An error occurred. Please try again later.',
                    success: null
                });
            }

            // Verify the current password
            bcrypt.compare(currentPassword, admin.password, (err, match) => {
                if (err) {
                    console.error('Error comparing passwords:', err);
                    return res.status(500).render('admin_change_password', {
                        boards,
                        error: 'An error occurred. Please try again later.',
                        success: null
                    });
                }

                if (!match) {
                    return res.render('admin_change_password', {
                        boards,
                        error: 'Current password is incorrect.',
                        success: null
                    });
                }

                // Hash the new password
                bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
                    if (err) {
                        console.error('Error hashing new password:', err);
                        return res.status(500).render('admin_change_password', {
                            boards,
                            error: 'An error occurred while updating the password.',
                            success: null
                        });
                    }

                    // Update the password in the database
                    db.run(`UPDATE admins SET password = ? WHERE id = ?`, [hashedPassword, admin.id], (err) => {
                        if (err) {
                            console.error('Error updating password:', err);
                            return res.status(500).render('admin_change_password', {
                                boards,
                                error: 'An error occurred while updating the password.',
                                success: null
                            });
                        }

                        res.render('admin_change_password', {
                            boards,
                            error: null,
                            success: 'Password updated successfully!'
                        });
                    });
                });
            });
        });
    });

    /* Route for the home page */
    app.get('/', (req, res) => {
        res.render('index', { page: 'home', boards, isAdmin: req.session.isAdmin });
    });

    /* Route for a board (redirects to the first page) */
    app.get('/:board', (req, res) => {
        const board = req.params.board;
        if (!boards.includes(board)) {
            return res.status(404).render('error', {
                status: 404,
                message: `Board "/${board}" not found.`,
                boards,
                isAdmin: req.session.isAdmin
            });
        }
        res.redirect(`/${board}/page/1`);
    });

    /* Route for a board with pagination */
    app.get('/:board/page/:page', (req, res) => {
        const board = req.params.board;
        const page = parseInt(req.params.page) || 1;
        const selectedTag = req.query.tag || null;
        if (!boards.includes(board) || page < 1) {
            return res.status(404).render('error', {
                status: 404,
                message: page < 1 ? 'Invalid page number.' : `Board "/${board}" not found.`,
                boards,
                isAdmin: req.session.isAdmin
            });
        }

        db.all(`
            SELECT DISTINCT tags
            FROM posts
            WHERE board = ? AND parent_id IS NULL AND tags IS NOT NULL
        `, [board], (err, tagRows) => {
            if (err) {
                console.error(err);
                return res.status(500).render('error', {
                    status: 500,
                    message: 'An error occurred while fetching tags. Please try again later.',
                    boards,
                    isAdmin: req.session.isAdmin
                });
            }

            const allTags = new Set();
            tagRows.forEach(row => {
                if (row.tags) {
                    row.tags.split(',').forEach(tag => {
                        const trimmedTag = tag.trim();
                        if (trimmedTag) allTags.add(trimmedTag);
                    });
                }
            });
            const uniqueTags = Array.from(allTags).sort();

            let countQuery = `
                SELECT COUNT(*) as total_threads
                FROM posts
                WHERE board = ? AND parent_id IS NULL
            `;
            const countParams = [board];
            if (selectedTag) {
                countQuery += ` AND tags LIKE ?`;
                countParams.push(`%${selectedTag}%`);
            }

            db.get(countQuery, countParams, (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).render('error', {
                        status: 500,
                        message: 'An error occurred while fetching threads. Please try again later.',
                        boards,
                        isAdmin: req.session.isAdmin
                    });
                }

                const totalThreads = result.total_threads;
                const totalPages = Math.min(Math.ceil(totalThreads / THREADS_PER_PAGE), MAX_PAGES);

                if (page > totalPages && totalThreads > 0) {
                    return res.status(404).render('error', {
                        status: 404,
                        message: `Page ${page} not found for board "/${board}".`,
                        boards,
                        isAdmin: req.session.isAdmin
                    });
                }

                if (totalThreads > MAX_THREADS) {
                    const threadsToDelete = totalThreads - MAX_THREADS;
                    db.run(`
                        DELETE FROM posts
                        WHERE id IN (
                            SELECT p.id
                            FROM posts p
                            LEFT JOIN posts r ON r.parent_id = p.id
                            WHERE p.board = ? AND p.parent_id IS NULL
                            GROUP BY p.id
                            ORDER BY COUNT(r.id) ASC, MAX(COALESCE(r.created_at, p.created_at)) ASC
                            LIMIT ?
                        )
                    `, [board, threadsToDelete], (err) => {
                        if (err) {
                            console.error('Error pruning threads:', err);
                        }
                    });
                }

                let threadQuery = `
                    SELECT 
                        p.id, 
                        p.content, 
                        p.image, 
                        p.thumbnail,
                        p.tags, 
                        p.created_at,
                        p.quote_id,
                        p.pinned,
                        p.ip_address,
                        MAX(COALESCE(r.created_at, p.created_at)) as last_activity,
                        COUNT(r.id) as reply_count
                    FROM posts p
                    LEFT JOIN posts r ON r.parent_id = p.id
                    WHERE p.board = ? AND p.parent_id IS NULL
                `;
                const threadParams = [board];
                if (selectedTag) {
                    threadQuery += ` AND p.tags LIKE ?`;
                    threadParams.push(`%${selectedTag}%`);
                }
                threadQuery += `
                    GROUP BY p.id
                    ORDER BY 
                        p.pinned DESC,
                        CASE 
                            WHEN COUNT(r.id) < ? THEN MAX(COALESCE(r.created_at, p.created_at))
                            ELSE p.created_at
                        END DESC
                    LIMIT ? OFFSET ?
                `;
                threadParams.push(BUMP_LIMIT, THREADS_PER_PAGE, (page - 1) * THREADS_PER_PAGE);

                db.all(threadQuery, threadParams, (err, threads) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).render('error', {
                            status: 500,
                            message: 'An error occurred while fetching threads. Please try again later.',
                            boards,
                            isAdmin: req.session.isAdmin
                        });
                    }

                    const previews = [];
                    let completed = 0;

                    if (threads.length === 0) {
                        return res.render('boards', { board, threads: [], previews, boards, page, totalPages, tags: uniqueTags, selectedTag, isAdmin: req.session.isAdmin });
                    }

                    threads.forEach(thread => {
                        const preview = {
                            thread_id: thread.id,
                            reply_count: thread.reply_count,
                            isBumpLimited: thread.reply_count >= BUMP_LIMIT,
                            pinned: thread.pinned,
                            ip_address: thread.ip_address,
                            posts: [{
                                id: thread.id,
                                content: convertTextToHtml(thread.content),
                                image: thread.image,
                                thumbnail: thread.thumbnail,
                                tags: thread.tags,
                                created_at: thread.created_at,
                                quote_id: thread.quote_id,
                                ip_address: thread.ip_address,
                                isVideo: thread.image && thread.image.match(/\.(mp4|webm)$/i)
                            }]
                        };

                        db.all(`
                            SELECT id, content, image, thumbnail, created_at, quote_id, ip_address
                            FROM posts
                            WHERE parent_id = ?
                            ORDER BY created_at DESC
                            LIMIT 2
                        `, [thread.id], (err, replies) => {
                            if (err) {
                                console.error(err);
                                return res.status(500).render('error', {
                                    status: 500,
                                    message: 'An error occurred while fetching replies. Please try again later.',
                                    boards,
                                    isAdmin: req.session.isAdmin
                                });
                            }

                            preview.posts.push(...replies.reverse().map(reply => ({
                                ...reply,
                                content: convertTextToHtml(reply.content),
                                thumbnail: reply.thumbnail,
                                ip_address: reply.ip_address,
                                isVideo: reply.image && reply.image.match(/\.(mp4|webm)$/i)
                            })));
                            previews.push(preview);
                            completed++;

                            if (completed === threads.length) {
                                previews.sort((a, b) => {
                                    const threadA = threads.find(t => t.id === a.thread_id);
                                    const threadB = threads.find(t => t.id === b.thread_id);
                                    if (threadA.pinned && !threadB.pinned) return -1;
                                    if (!threadA.pinned && threadB.pinned) return 1;
                                    const orderA = threadA.reply_count < BUMP_LIMIT ? threadA.last_activity : threadA.created_at;
                                    const orderB = threadB.reply_count < BUMP_LIMIT ? threadB.last_activity : threadB.created_at;
                                    return new Date(orderB) - new Date(orderA);
                                });
                                res.render('boards', { board, threads, previews, boards, page, totalPages, tags: uniqueTags, selectedTag, isAdmin: req.session.isAdmin });
                            }
                        });
                    });
                });
            });
        });
    });

    /* Route for viewing a specific thread */
    app.get('/:board/:id', (req, res) => {
        const { board, id } = req.params;
        if (!boards.includes(board)) {
            return res.status(404).render('error', {
                status: 404,
                message: `Board "/${board}" not found.`,
                boards,
                isAdmin: req.session.isAdmin
            });
        }

        db.get(`
            SELECT id, content, image, thumbnail, tags, created_at, quote_id, pinned, ip_address
            FROM posts
            WHERE id = ? AND board = ? AND parent_id IS NULL
        `, [id, board], (err, thread) => {
            if (err || !thread) {
                return res.status(404).render('error', {
                    status: 404,
                    message: err ? 'An error occurred while fetching the thread. Please try again later.' : `Thread #${id} not found on board "/${board}".`,
                    boards,
                    isAdmin: req.session.isAdmin
                });
            }

            thread.isVideo = thread.image && thread.image.match(/\.(mp4|webm)$/i);
            thread.thumbnail = thread.thumbnail;
            thread.content = convertTextToHtml(thread.content);
            thread.ip_address = thread.ip_address;

            db.all(`
                SELECT id, content, image, thumbnail, created_at, quote_id, ip_address
                FROM posts
                WHERE parent_id = ?
                ORDER BY created_at ASC
            `, [id], (err, replies) => {
                if (err) {
                    console.error(err);
                    return res.status(500).render('error', {
                        status: 500,
                        message: 'An error occurred while fetching replies. Please try again later.',
                        boards,
                        isAdmin: req.session.isAdmin
                    });
                }

                replies = replies.map(reply => ({
                    ...reply,
                    content: convertTextToHtml(reply.content),
                    thumbnail: reply.thumbnail,
                    ip_address: reply.ip_address,
                    isVideo: reply.image && reply.image.match(/\.(mp4|webm)$/i)
                }));

                res.render('index', { page: 'thread', board, thread, replies, boards, isAdmin: req.session.isAdmin });
            });
        });
    });

    /* Route to ban a user by IP (admin only) */
    app.post('/admin/ban', isAdmin, (req, res) => {
        const { ip_address, reason, board, thread_id } = req.body;

        db.run(`
            INSERT INTO bans (ip_address, reason, banned_at)
            VALUES (?, ?, datetime('now'))
        `, [ip_address, reason || 'No reason provided'], (err) => {
            if (err) {
                console.error('Error banning user:', err);
                return res.status(500).render('error', {
                    status: 500,
                    message: 'Error banning user.',
                    boards,
                    isAdmin: req.session.isAdmin
                });
            }

            if (thread_id) {
                res.redirect(`/${board}/${thread_id}`);
            } else {
                res.redirect(`/${board}`);
            }
        });
    });

    /* Route to pin/unpin a thread (admin only) */
    app.post('/admin/pin/:board/:id', isAdmin, (req, res) => {
        const { board, id } = req.params;

        db.get(`SELECT pinned FROM posts WHERE id = ? AND board = ? AND parent_id IS NULL`, [id, board], (err, thread) => {
            if (err || !thread) {
                return res.status(404).render('error', {
                    status: 404,
                    message: err ? 'Error fetching thread.' : `Thread #${id} not found.`,
                    boards,
                    isAdmin: req.session.isAdmin
                });
            }

            const newPinnedStatus = thread.pinned ? 0 : 1;
            db.run(`UPDATE posts SET pinned = ? WHERE id = ?`, [newPinnedStatus, id], (err) => {
                if (err) {
                    console.error('Error pinning thread:', err);
                    return res.status(500).render('error', {
                        status: 500,
                        message: 'Error pinning thread.',
                        boards,
                        isAdmin: req.session.isAdmin
                    });
                }
                res.redirect(`/${board}`);
            });
        });
    });

    /* Route for creating a new post or reply, with rate limiting */
    app.post('/:board', postLimiter, upload, (req, res) => {
        const { board } = req.params;

        if (!boards.includes(board)) {
            return res.status(404).render('error', {
                status: 404,
                message: `Board "/${board}" not found.`,
                boards,
                isAdmin: req.session.isAdmin
            });
        }

        const { content, parent_id, quote_id, tags } = req.body;
        const { thread_id } = req.query;
        const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const media = req.file ? `/uploads/${req.file.filename}` : null;

        const parentIdValue = (parent_id && parent_id.trim() !== '') 
            ? parseInt(parent_id, 10) 
            : (thread_id && thread_id.trim() !== '' ? parseInt(thread_id, 10) : null);
        const quoteIdValue = quote_id && quote_id.trim() !== '' ? parseInt(quote_id, 10) : null;
        const tagsValue = parentIdValue === null ? (tags || null) : null;

        if (media) {
            const filePath = path.join(__dirname, 'public', media);
            const isVideo = media.match(/\.(mp4|webm)$/i);

            const validationPromise = isVideo ? validateVideo(filePath) : validateImage(filePath);

            validationPromise
                .then(() => {
                    if (isVideo) {
                        return generateThumbnail(filePath).then(thumbnailPath => {
                            savePost(board, content, media, thumbnailPath, parentIdValue, quoteIdValue, tagsValue, userIp, res);
                        });
                    } else {
                        savePost(board, content, media, null, parentIdValue, quoteIdValue, tagsValue, userIp, res);
                    }
                })
                .catch((validationErr) => {
                    const fs = require('fs');
                    fs.unlink(filePath, (unlinkErr) => {
                        if (unlinkErr) {
                            console.error('Error deleting invalid file:', unlinkErr);
                        }
                        res.status(400).render('error', {
                            status: 400,
                            message: validationErr.message,
                            boards,
                            isAdmin: req.session.isAdmin
                        });
                    });
                });
        } else {
            savePost(board, content, null, null, parentIdValue, quoteIdValue, tagsValue, userIp, res);
        }
    });

    /* Helper function to save a post to the database */
    function savePost(board, content, media, thumbnail, parent_id, quote_id, tags, ip_address, res) {
        db.run(`
            INSERT INTO posts (board, content, image, thumbnail, parent_id, quote_id, tags, created_at, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
        `, [board, content, media, thumbnail, parent_id, quote_id, tags, ip_address], function(err) {
            if (err) {
                console.error(err);
                return res.status(500).render('error', {
                    status: 500,
                    message: 'An error occurred while saving your post. Please try again later.',
                    boards,
                    isAdmin: req.session.isAdmin
                });
            }

            const redirectId = parent_id || this.lastID;
            res.redirect(`/${board}/${redirectId}`);
        });
    }

    /* Start the Express server on port 3000 */
    app.listen(3000, () => {
        console.log('Miyeok running on http://localhost:3000');
    });
}).catch((err) => {
    console.error('Failed to initialize database:', err.message);
    process.exit(1);
});