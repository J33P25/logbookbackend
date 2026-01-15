const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'attendance_db',
    password: process.env.DB_PASSWORD || 'newpassword',
    port: 5432,
});

const JWT_SECRET = process.env.JWT_SECRET || 'supreme_secret_999';
const generate6DigitToken = () => Math.floor(100000 + Math.random() * 900000).toString();

// --- AUTH MIDDLEWARES ---
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No Token" });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Access Denied" });
    next();
};
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.rows[0].id, role: user.rows[0].role,student_id: user.rows[0].student_id }, JWT_SECRET);
    res.json({ token, role: user.rows[0].role });
});
// ==========================================
// 1. DEPARTMENT CRUD
// ==========================================
app.post('/api/admin/depts', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, code } = req.body;
    const result = await pool.query('INSERT INTO departments (dept_name, dept_code) VALUES ($1, $2) RETURNING *', [name, code]);
    res.status(201).json(result.rows[0]);
});

app.get('/api/admin/depts', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM departments');
    res.json(result.rows);
});

app.put('/api/admin/depts/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, code } = req.body;
    await pool.query('UPDATE departments SET dept_name = $1, dept_code = $2 WHERE id = $3', [name, code, req.params.id]);
    res.json({ message: "Department Updated" });
});

app.delete('/api/admin/depts/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM departments WHERE id = $1', [req.params.id]);
    res.json({ message: "Department Deleted" });
});

// ==========================================
// 2. BATCH CRUD
// ==========================================
app.post('/api/admin/batches', authenticateToken, authorize(['admin']), async (req, res) => {
    const { dept_id, start_year, end_year, batch_name } = req.body;
    const result = await pool.query('INSERT INTO batches (dept_id, start_year, end_year, batch_name) VALUES ($1,$2,$3,$4) RETURNING *', [dept_id, start_year, end_year, batch_name]);
    res.json(result.rows[0]);
});

app.get('/api/admin/batches', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT b.*, d.dept_code FROM batches b JOIN departments d ON b.dept_id = d.id');
    res.json(result.rows);
});

app.put('/api/admin/batches/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { start_year, end_year, batch_name } = req.body;
    await pool.query('UPDATE batches SET start_year=$1, end_year=$2, batch_name=$3 WHERE id=$4', [start_year, end_year, batch_name, req.params.id]);
    res.json({ message: "Batch Updated" });
});

app.delete('/api/admin/batches/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM batches WHERE id = $1', [req.params.id]);
    res.json({ message: "Batch Deleted" });
});

// ==========================================
// 3. SECTION CRUD
// ==========================================
app.post('/api/admin/sections', authenticateToken, authorize(['admin']), async (req, res) => {
    const { batch_id, section_name } = req.body;
    const result = await pool.query('INSERT INTO sections (batch_id, section_name) VALUES ($1, $2) RETURNING *', [batch_id, section_name]);
    res.json(result.rows[0]);
});

app.get('/api/admin/sections', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT s.*, b.batch_name FROM sections s JOIN batches b ON s.batch_id = b.id');
    res.json(result.rows);
});

app.put('/api/admin/sections/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { section_name } = req.body;
    await pool.query('UPDATE sections SET section_name = $1 WHERE id = $2', [section_name, req.params.id]);
    res.json({ message: "Section Updated" });
});

app.delete('/api/admin/sections/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM sections WHERE id = $1', [req.params.id]);
    res.json({ message: "Section Deleted" });
});


// A. GET ALL FACULTY (Even those without accounts)
app.get('/api/admin/faculty', authenticateToken, async (req, res) => {
    try {
        const sql = `
            SELECT 
                f.id as profile_id, 
                f.faculty_name, 
                f.email, 
                f.dept_id, 
                d.dept_code, 
                f.authorization_key, 
                u.id as user_id -- This will be null if no account exists
            FROM faculty_profiles f
            JOIN departments d ON f.dept_id = d.id
            LEFT JOIN users u ON f.user_id = u.id
            ORDER BY f.faculty_name ASC`;
        const result = await pool.query(sql);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// B. STEP 1: CREATE FACULTY PROFILE (Directory Entry Only)
app.post('/api/admin/faculty-profile', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, email, dept_id, auth_key } = req.body;
    try {
        await pool.query(
            'INSERT INTO faculty_profiles (faculty_name, email, dept_id, authorization_key) VALUES ($1, $2, $3, $4)',
            [name, email, dept_id, auth_key]
        );
        res.json({ message: "Faculty Profile Added" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// C. STEP 2: CREATE LOGIN FOR EXISTING PROFILE
app.post('/api/admin/faculty-login', authenticateToken, authorize(['admin']), async (req, res) => {
    const { faculty_profile_id, password } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        // 1. Get Email from Profile
        const profile = await client.query('SELECT email FROM faculty_profiles WHERE id = $1', [faculty_profile_id]);
        if (profile.rows.length === 0) throw new Error("Profile not found");
        const email = profile.rows[0].email;

        // 2. Create User Account
        const hash = await bcrypt.hash(password, 10);
        const userRes = await client.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, \'faculty\') RETURNING id',
            [email, hash]
        );
        const newUserId = userRes.rows[0].id;

        // 3. Link User to Profile
        await client.query(
            'UPDATE faculty_profiles SET user_id = $1 WHERE id = $2',
            [newUserId, faculty_profile_id]
        );

        await client.query('COMMIT');
        res.json({ message: "User account created and linked to faculty profile" });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: e.message });
    } finally {
        client.release();
    }
});
app.put('/api/admin/faculty/:userId', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, auth_key, dept_id } = req.body;
    await pool.query('UPDATE faculty_profiles SET faculty_name=$1, authorization_key=$2, dept_id=$3 WHERE user_id=$4', [name, auth_key, dept_id, req.params.userId]);
    res.json({ message: "Faculty Profile Updated" });
});

app.delete('/api/admin/faculty/:userId', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM users WHERE id = $1 AND role = \'faculty\'', [req.params.userId]);
    res.json({ message: "Faculty Deleted" });
});

// ==========================================
// 5. STUDENT CRUD & CR PROMOTION
// ==========================================
app.post('/api/admin/students', authenticateToken, authorize(['admin']), async (req, res) => {
    const { roll, name, email, section_id } = req.body;
    await pool.query('INSERT INTO students (roll_number, full_name, email, section_id) VALUES ($1,$2,$3,$4)', [roll, name, email, section_id]);
    res.json({ message: "Student Added" });
});

app.get('/api/admin/students', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT s.*, sec.section_name FROM students s JOIN sections sec ON s.section_id = sec.id');
    res.json(result.rows);
});

app.put('/api/admin/students/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, roll, email, section_id } = req.body;
    await pool.query('UPDATE students SET full_name=$1, roll_number=$2, email=$3, section_id=$4 WHERE id=$5', [name, roll, email, section_id, req.params.id]);
    res.json({ message: "Student Updated" });
});

app.delete('/api/admin/students/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM students WHERE id = $1', [req.params.id]);
    res.json({ message: "Student Deleted" });
});

app.post('/api/admin/promote-cr', authenticateToken, authorize(['admin']), async (req, res) => {
    const { student_id, password } = req.body;
    const student = await pool.query('SELECT email FROM students WHERE id = $1', [student_id]);
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password_hash, role, student_id) VALUES ($1,$2,\'cr\',$3)', [student.rows[0].email, hash, student_id]);
    res.json({ message: "Promoted to CR" });
});

// ==========================================
// 6. COURSE CRUD
// ==========================================
app.post('/api/admin/courses', authenticateToken, authorize(['admin']), async (req, res) => {
    const { code, name, credits, dept_id } = req.body;
    await pool.query('INSERT INTO courses (course_code, course_name, credits, dept_id) VALUES ($1,$2,$3,$4)', [code, name, credits, dept_id]);
    res.json({ message: "Course Created" });
});

app.get('/api/admin/courses', authenticateToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM courses');
    res.json(result.rows);
});

app.put('/api/admin/courses/:code', authenticateToken, authorize(['admin']), async (req, res) => {
    const { name, credits } = req.body;
    await pool.query('UPDATE courses SET course_name=$1, credits=$2 WHERE course_code=$3', [name, credits, req.params.code]);
    res.json({ message: "Course Updated" });
});

app.delete('/api/admin/courses/:code', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM courses WHERE course_code = $1', [req.params.code]);
    res.json({ message: "Course Deleted" });
});

// ==========================================
// 7. TIMETABLE CRUD & VIEW
// ==========================================
app.post('/api/admin/timetable', authenticateToken, authorize(['admin']), async (req, res) => {
    const { section_id, semester, day, slot, course_code, faculty_id, room } = req.body;
    await pool.query('INSERT INTO timetable (section_id, semester, day, slot_number, course_code, faculty_profile_id, room_info) VALUES ($1,$2,$3,$4,$5,$6,$7)', [section_id, semester, day, slot, course_code, faculty_id, room]);
    res.json({ message: "Slot Added" });
});

app.get('/api/common/timetable', authenticateToken, async (req, res) => {
    const { section_id, semester } = req.query;
    const sql = `SELECT t.*, c.course_name, f.faculty_name FROM timetable t 
                 JOIN courses c ON t.course_code = c.course_code 
                 JOIN faculty_profiles f ON t.faculty_profile_id = f.id 
                 WHERE section_id = $1 AND semester = $2 ORDER BY day, slot_number`;
    const result = await pool.query(sql, [section_id, semester]);
    res.json(result.rows);
});

app.put('/api/admin/timetable/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    const { day, slot, course_code, faculty_id, room } = req.body;
    await pool.query('UPDATE timetable SET day=$1, slot_number=$2, course_code=$3, faculty_profile_id=$4, room_info=$5 WHERE id=$6', [day, slot, course_code, faculty_id, room, req.params.id]);
    res.json({ message: "Slot Updated" });
});

app.delete('/api/admin/timetable/:id', authenticateToken, authorize(['admin']), async (req, res) => {
    await pool.query('DELETE FROM timetable WHERE id = $1', [req.params.id]);
    res.json({ message: "Slot Deleted" });
});


app.put('/api/faculty/regen-token', authenticateToken, authorize(['faculty']), async (req, res) => {
    const newToken = generate6DigitToken();
    await pool.query('UPDATE faculty_profiles SET authorization_key = $1 WHERE user_id = $2', [newToken, req.user.id]);
    res.json({ message: "New Token Generated", token: newToken });
});




app.get('/api/cr/my-courses', authenticateToken, authorize(['cr']), async (req, res) => {
    const sql = `
        SELECT DISTINCT c.*
        FROM courses c
        JOIN timetable t ON c.course_code = t.course_code
        JOIN students s ON t.section_id = s.section_id
        WHERE s.id = $1
        ORDER BY c.course_name ASC`;
    try {
        console.log(req.user.student_id);
        const result = await pool.query(sql, [req.user.student_id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// app.post('/api/cr/attendance', authenticateToken, authorize(['cr']), async (req, res) => {
//     const { timetable_id, date, records, selected_course_code, is_free } = req.body;
//     const client = await pool.connect();
//     try {
//         await client.query('BEGIN');

//         // 1. Get Scheduled Course
//         const tt = await client.query('SELECT course_code FROM timetable WHERE id = $1', [timetable_id]);
//         const scheduledCourse = tt.rows[0].course_code;

//         let category = 'normal';
//         if (is_free) category = 'free';
//         else if (selected_course_code !== scheduledCourse) category = 'swap';

//         // 2. Create Session
//         const sessSql = `
//             INSERT INTO attendance_sessions 
//             (timetable_id, session_date, marked_by_user_id, session_category, actual_course_code) 
//             VALUES ($1, $2, $3, $4, $5) RETURNING id`;
//         const sessRes = await client.query(sessSql, [timetable_id, date, req.user.id, category, selected_course_code]);
//         const sessionId = sessRes.rows[0].id;

//         // 3. Insert Records (Skip if free)
//         if (category !== 'free') {
//             for (let r of records) {
//                 await client.query('INSERT INTO attendance_records (session_id, student_id, status) VALUES ($1, $2, $3)', 
//                 [sessionId, r.id, r.status]);
//             }
//         }

//         await client.query('COMMIT');
//         res.json({ message: "Attendance processed", sessionId, category });
//     } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: e.message }); } finally { client.release(); }
// });


app.post('/api/cr/attendance', authenticateToken, authorize(['cr', 'faculty', 'admin']), async (req, res) => {
    const { timetable_id, date, records, selected_course_code, is_free } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        // 1. Fetch Scheduled Data (Original Course, Original Faculty, Section ID)
        // We need section_id to find who teaches the "Selected Course" for this class
        const ttResult = await client.query(
            'SELECT course_code, faculty_profile_id, section_id FROM timetable WHERE id = $1', 
            [timetable_id]
        );
        
        if (ttResult.rows.length === 0) throw new Error("Timetable slot not found");
        
        const scheduledCourse = ttResult.rows[0].course_code;
        const originalFacultyId = ttResult.rows[0].faculty_profile_id; // The Requesting Faculty (Owner of slot)
        const sectionId = ttResult.rows[0].section_id;

        // 2. Determine Session Category
        let category = 'normal';
        if (is_free) category = 'free';
        else if (selected_course_code !== scheduledCourse) category = 'swap';

        // 3. Insert into attendance_sessions
        const sessSql = `
            INSERT INTO attendance_sessions 
            (timetable_id, session_date, marked_by_user_id, session_category, actual_course_code) 
            VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        
        const sessRes = await client.query(sessSql, [
            timetable_id, 
            date, 
            req.user.id, 
            category, 
            is_free ? null : selected_course_code
        ]);
        const sessionId = sessRes.rows[0].id;

        // 4. Insert Attendance Records (Skip if free)
        if (category !== 'free' && records && records.length > 0) {
            for (let r of records) {
                const status = r.status.toLowerCase(); 
                await client.query(
                    'INSERT INTO attendance_records (session_id, student_id, status) VALUES ($1, $2, $3)', 
                    [sessionId, r.id, status]
                );
            }
        }

        // ============================================================
        // 5. AUTO-LOG SWAP ENTRY (If Swap or Free)
        // ============================================================
        if (category === 'swap' || category === 'free') {
            
            let targetFacultyId = null;

            if (category === 'swap') {
                // LOGIC: Find the Faculty who teaches the "Selected Course" to this "Section"
                // We look for ANY slot in the timetable where this course is taught to this section
                const targetFacRes = await client.query(
                    `SELECT faculty_profile_id FROM timetable 
                     WHERE section_id = $1 AND course_code = $2 
                     LIMIT 1`,
                    [sectionId, selected_course_code]
                );

                if (targetFacRes.rows.length > 0) {
                    targetFacultyId = targetFacRes.rows[0].faculty_profile_id;
                } else {
                    // Fallback: If logged-in user is a faculty member, assume they are the substitute
                    if (req.user.role === 'faculty') {
                        const loggedInFac = await client.query(
                            'SELECT id FROM faculty_profiles WHERE user_id = $1', 
                            [req.user.id]
                        );
                        if (loggedInFac.rows.length > 0) targetFacultyId = loggedInFac.rows[0].id;
                    }
                }
            }

            const swapReason = category === 'free' 
                ? 'Class declared Free during attendance marking' 
                : `Course changed from ${scheduledCourse} to ${selected_course_code}`;

            await client.query(`
                INSERT INTO class_swaps 
                (source_timetable_id, requesting_faculty_id, target_faculty_id, requested_date, reason, status)
                VALUES ($1, $2, $3, $4, $5, 'approved')`,
                [timetable_id, originalFacultyId, targetFacultyId, date, swapReason]
            );
        }

        await client.query('COMMIT');
        res.json({ message: "Attendance processed and swap logged", sessionId, category });

    } catch (e) { 
        await client.query('ROLLBACK'); 
        console.error(e);
        res.status(500).json({ error: e.message }); 
    } finally { 
        client.release(); 
    }
});

app.get('/api/common/week-grid', authenticateToken, async (req, res) => {
    try {
        const { section_id, start_date, semester } = req.query; 

        const sql = `
            SELECT 
                t.*, 
                c.course_name,                  -- Scheduled Course Name
                f.faculty_name, 
                sess.id AS session_id,
                sess.session_category, 
                sess.session_date,
                sess.actual_course_code,        -- <--- ADDED: The Swapped Course Code
                ac.course_name AS actual_course_name -- <--- ADDED: The Swapped Course Name
            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            JOIN faculty_profiles f ON t.faculty_profile_id = f.id 
            
            -- Join Attendance Session to check status
            LEFT JOIN attendance_sessions sess 
                ON sess.timetable_id = t.id 
                AND sess.session_date = (
                    $2::date + (CASE t.day 
                        WHEN 'Mon' THEN 0 
                        WHEN 'Tue' THEN 1
                        WHEN 'Wed' THEN 2 
                        WHEN 'Thu' THEN 3 
                        WHEN 'Fri' THEN 4
                        ELSE 0 
                    END)
                )
            
            -- Join Courses AGAIN to get the name of the 'Actual/Swapped' course
            LEFT JOIN courses ac ON sess.actual_course_code = ac.course_code

            WHERE t.section_id = $1 AND t.semester = $3
            ORDER BY t.day, t.slot_number`;

        const result = await pool.query(sql, [section_id, start_date, semester]);
        res.json(result.rows);

    } catch (err) {
        console.error("Week Grid Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/common/timetable-by-class', authenticateToken, async (req, res) => {
    try {
        const { section_id, semester } = req.query;

        if (!section_id || !semester) {
            return res.status(400).json({ error: "section_id and semester are required" });
        }

        // UPDATED JOIN: t.faculty_profile_id = f.id
        const sql = `
            SELECT 
                t.*,
                c.course_name,
                f.faculty_name
            FROM timetable t
            JOIN courses c ON t.course_code = c.course_code
            JOIN faculty_profiles f ON t.faculty_profile_id = f.id
            WHERE t.section_id = $1 AND t.semester = $2
            ORDER BY t.day, t.slot_number
        `;

        const result = await pool.query(sql, [section_id, semester]);
        res.json(result.rows);

    } catch (err) {
        res.status(500).json({ error: "Internal server error" });
    }
});


// Get all attendance sessions for a specific timetable slot (Admin View)
app.get('/api/admin/sessions-by-timetable/:ttId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const sql = `
            SELECT sess.id, sess.session_date, sess.is_verified_by_faculty, u.email as marked_by
            FROM attendance_sessions sess
            JOIN users u ON sess.marked_by_user_id = u.id
            WHERE sess.timetable_id = $1
            ORDER BY sess.session_date DESC`;
        const result = await pool.query(sql, [req.params.ttId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get detailed student records for a specific session ID
app.get('/api/admin/records-by-session/:sessionId', authenticateToken, authorize(['admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.roll_number, s.full_name, r.status
            FROM attendance_records r
            JOIN students s ON r.student_id = s.id
            WHERE r.session_id = $1
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.params.sessionId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Get students for a specific timetable slot
app.get('/api/cr/students-by-timetable/:ttId', authenticateToken, authorize(['cr', 'admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.* 
            FROM students s 
            JOIN timetable t ON s.section_id = t.section_id 
            WHERE t.id = $1
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.params.ttId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/cr/students-by-studentid', authenticateToken, authorize(['cr', 'admin']), async (req, res) => {
    try {
        const sql = `
            SELECT s.* 
            FROM students s 
            WHERE s.section_id=(select section_id from students where id=$1)
            ORDER BY s.roll_number ASC`;
        const result = await pool.query(sql, [req.user.student_id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/faculty/verify/:sessionId', authenticateToken, authorize(['faculty']), async (req, res) => {
    const { token } = req.body;
    const profile = await pool.query('SELECT authorization_key FROM faculty_profiles WHERE user_id = $1', [req.user.id]);
    if (profile.rows[0].authorization_key !== token) return res.status(401).json({ error: "Invalid 6-digit Token" });
    
    await pool.query('UPDATE attendance_sessions SET is_verified_by_faculty = true, verified_at = NOW() WHERE id = $1', [req.params.sessionId]);
    res.json({ message: "Attendance verified and locked" });
});




// Get students filtered by Section (and optionally Semester if your DB supports it, otherwise Section implies the group)
app.get('/api/admin/students-by-filter', authenticateToken, async (req, res) => {
    try {
        const { section_id } = req.query; // We filter primarily by section as it contains the students

        if (!section_id) return res.status(400).json({ error: "Section ID is required" });

        const sql = `
            SELECT s.id, s.roll_number, s.full_name, s.email, sec.section_name, b.batch_name, u.role
            FROM students s
            JOIN sections sec ON s.section_id = sec.id
            JOIN batches b ON sec.batch_id = b.id
            LEFT JOIN users u ON s.id = u.student_id -- Join to see if they are already a CR
            WHERE s.section_id = $1
            ORDER BY s.roll_number ASC`;
            
        const result = await pool.query(sql, [section_id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});




// GET Attendance Report / Shortage List
app.get('/api/admin/attendance-report', authenticateToken, async (req, res) => {
    const { section_id, course_code, threshold } = req.query; // e.g., threshold = 75

    // SQL Logic:
    // 1. Get all students in the section
    // 2. Count Total Sessions (sess.id) for the course(s) linked to this section
    // 3. Count "Present" records for each student
    const sql = `
        WITH SessionCounts AS (
            SELECT 
                sess.actual_course_code,
                COUNT(sess.id) as total_sessions
            FROM attendance_sessions sess
            JOIN timetable t ON sess.timetable_id = t.id
            WHERE t.section_id = $1
            AND ($2::text = 'ALL' OR sess.actual_course_code = $2)
            AND sess.session_category != 'free' -- Don't count free periods
            GROUP BY sess.actual_course_code
        ),
        StudentAttendance AS (
            SELECT 
                s.id as student_id,
                s.roll_number,
                s.full_name,
                sess.actual_course_code,
                COUNT(CASE WHEN r.status = 'Present' THEN 1 END) as attended_sessions
            FROM students s
            JOIN attendance_records r ON s.id = r.student_id
            JOIN attendance_sessions sess ON r.session_id = sess.id
            JOIN timetable t ON sess.timetable_id = t.id
            WHERE s.section_id = $1
            AND ($2::text = 'ALL' OR sess.actual_course_code = $2)
            AND sess.session_category != 'free'
            GROUP BY s.id, sess.actual_course_code
        )
        SELECT 
            sa.roll_number,
            sa.full_name,
            sa.actual_course_code as subject,
            COALESCE(sc.total_sessions, 0) as total,
            sa.attended_sessions as attended,
            ROUND((sa.attended_sessions::decimal / NULLIF(sc.total_sessions, 0)) * 100, 1) as percentage
        FROM StudentAttendance sa
        JOIN SessionCounts sc ON sa.actual_course_code = sc.actual_course_code
        WHERE ($3::int IS NULL OR (sa.attended_sessions::decimal / NULLIF(sc.total_sessions, 0)) * 100 < $3)
        ORDER BY sa.roll_number, sa.actual_course_code;
    `;

    try {
        const result = await pool.query(sql, [section_id, course_code || 'ALL', threshold || 75]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.listen(3000, () => console.log("Server Running on 3000"));