const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(cors());

// Serve the frontend UI files seamlessly from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Secure Database Connection Initialization
const SUPABASE_URL = "https://tzrjomxyhziqkxipdwyq.supabase.co"; 
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR6cmpvbXh5aHppcWt4aXBkd3lxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkzMDA1ODAsImV4cCI6MjA5NDg3NjU4MH0.Z22iLye54Ryu3cKu75ntwn9_6vHAOZ5iovYDZg2XwbY"; 
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

console.log("📡 SERVER RE-INITIALIZED: Pointed at active Supabase project.");

// Session Guard Secret Cryptographic Passphrase
const JWT_SECRET = "PATTS_AERO_ENGINEERING_SECURE_TOKEN_KEY_998877";

/* --- SECURITY GUARD MIDDLEWARE: TOKEN DECRYPTION --- */
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Access Denied: Missing Session Token" });

    jwt.verify(token, JWT_SECRET, (err, studentPayload) => {
        if (err) return res.status(403).json({ error: "Session Expired. Please sign in again." });
        req.studentNo = studentPayload.studentNo;
        next();
    });
}

/* --- SYSTEM API ENDPOINTS --- */

// 1. SECURE LOGIN ROUTE
app.post('/api/student/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data: student, error } = await supabase
            .from('students')
            .select('*')
            .eq('student_no', email.trim())
            .maybeSingle();

        if (error || !student) {
            return res.status(404).json({ success: false, error: "Student registration record not found." });
        }

        // 🔒 SECURE PASSWORD EVALUATION LOCKdown:
        if (student.password_hash) {
            if (password !== student.password_hash) {
                return res.status(401).json({ success: false, error: "Authentication failure: Invalid credentials." });
            }
        } else {
            if (password !== "password123") {
                return res.status(401).json({ success: false, error: "Authentication failure: Invalid default credentials." });
            }
        }

        const token = jwt.sign({ studentNo: student.student_no }, JWT_SECRET, { expiresIn: '1h' });

        return res.status(200).json({ 
            success: true, 
            token: token,
            student: student 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "Internal ledger component engine failure." });
    }
});

// 2. LIVE DASHBOARD ANCHOR ROUTE (RE-FIXED TRANSACTIONS FALLBACK MAP)
app.get('/api/student/dashboard', authenticateToken, async (req, res) => {
    try {
        const { data: student, error: studentErr } = await supabase
            .from('students')
            .select('*')
            .eq('student_no', req.studentNo)
            .single();

        if (studentErr || !student) {
            return res.status(404).json({ success: false, error: "Student profile records missing." });
        }

        let stringStatus = "LOCKED";
        if (student.status === 0 || student.status === "0") {
            stringStatus = "ACTIVE";
        }

        console.log(`🔍 Querying transactions for Student No: ${student.student_no} | UID: ${student.uid}`);

        // Step A: Look up histories tied directly to the institutional student number value string
        let { data: transactions, error: txErr } = await supabase
            .from('transactions')
            .select('*')
            .eq('student_no', student.student_no)
            .order('timestamp', { ascending: false });

        // Step B: Robust Error Recovery. If student_no column filter comes back blank, query by card physical UID
        if (!transactions || transactions.length === 0) {
            console.log("⚠️ No history matched 'student_no'. Attempting backup matching column: uid...");
            const { data: fallbackTx } = await supabase
                .from('transactions')
                .select('*')
                .eq('uid', student.uid)
                .order('timestamp', { ascending: false });
            
            if (fallbackTx) {
                transactions = fallbackTx;
            }
        }

        console.log(`📊 Total ledger elements retrieved successfully: [${transactions ? transactions.length : 0}] rows.`);

        res.json({ 
            success: true, 
            name: student.name,
            studentNo: student.student_no,
            course: student.course,
            balance: parseFloat(student.balance) || 0.00,
            uid: student.uid || "---------",
            status: stringStatus,
            transactions: transactions || []
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "Ledger syncing execution crash." });
    }
});

// 3. LOCK STATUS TOGGLE ROUTE
app.post('/api/student/toggle-lock', authenticateToken, async (req, res) => {
    try {
        const { data: student, error: fetchErr } = await supabase
            .from('students')
            .select('status')
            .eq('student_no', req.studentNo)
            .single();

        if (fetchErr || !student) return res.status(404).json({ error: "Profile trace failed." });

        const newStatusInt = (student.status === 0) ? 1 : 0;

        await supabase
            .from('students')
            .update({ status: newStatusInt })
            .eq('student_no', req.studentNo);

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Failed to alter card state flag." });
    }
});

// 4. UPDATE SYSTEM PASSWORD
app.post('/api/student/change-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters long." });

    try {
        const { data: student } = await supabase
            .from('students')
            .select('password_hash')
            .eq('student_no', req.studentNo)
            .single();

        if (student.password_hash && student.password_hash !== oldPassword) {
            return res.status(400).json({ error: "Current validation password confirmation failed." });
        }
        if (!student.password_hash && oldPassword !== "password123") {
            return res.status(400).json({ error: "Current validation password confirmation failed." });
        }

        await supabase
            .from('students')
            .update({ password_hash: newPassword })
            .eq('student_no', req.studentNo);

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Database exception encountered." });
    }
});

// Fallback catch-all single-page routing execution map
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(3000, () => console.log('🚀 PATTS AeroCard Web Server Online at http://localhost:3000'));