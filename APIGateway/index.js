const e1      = require('express');
const proxy   = require('http-proxy').createProxyServer();
const jwt     = require('jsonwebtoken');
require('dotenv').config();

const app        = e1();
const JWT_SECRET = process.env.JWT_SECRET || 'mysecretkey';

app.use(e1.json());
app.use(e1.urlencoded({ extended: true }));

// ─── IN-MEMORY USERS ─────────────────────────────────────────────────────────
const users = [
    { id: 1, name: 'Dapravith', email: 'dapravith@example.com', password: '1234', role: 'student' },
    { id: 2, name: 'Dara',      email: 'dara@example.com',      password: '1234', role: 'student' },
    { id: 3, name: 'Mr. Sokha', email: 'sokha@example.com',     password: '1234', role: 'teacher' },
    { id: 4, name: 'Admin',     email: 'admin@example.com',     password: '1234', role: 'admin'   },
];

// ─── IN-MEMORY EVENT LOGS ─────────────────────────────────────────────────────
let eventLogs = [];
let logId     = 1;

// ─── EVENT TRACKER ────────────────────────────────────────────────────────────
function trackEvent({ userId, userName, userRole, service, method, path, statusCode, duration, ip, note }) {
    const log = {
        id:         logId++,
        timestamp:  new Date().toISOString(),
        userId:     userId   || null,
        userName:   userName || 'anonymous',
        userRole:   userRole || 'unknown',
        service,
        method,
        path,
        statusCode: statusCode || null,
        duration:   duration   ? `${duration}ms` : null,
        ip,
        note:       note || null,
    };
    eventLogs.push(log);
    console.log(`[EVENT] ${log.timestamp} | ${log.userRole.toUpperCase()} "${log.userName}" → ${log.service} | ${log.method} ${log.path} | ${log.statusCode} | ${log.duration}`);
    return log;
}

// ─── PROXY TRACKING MIDDLEWARE ────────────────────────────────────────────────
function proxyWithTracking(req, res, target, service) {
    const startTime = Date.now();
    const originalWriteHead = res.writeHead.bind(res);
    res.writeHead = function (statusCode, ...args) {
        trackEvent({
            userId:    req.user?.id,
            userName:  req.user?.name,
            userRole:  req.user?.role,
            service,
            method:    req.method,
            path:      req.url,
            statusCode,
            duration:  Date.now() - startTime,
            ip:        req.ip || req.connection.remoteAddress,
        });
        return originalWriteHead(statusCode, ...args);
    };
    proxy.web(req, res, { target });
}

// ─── PROXY ERROR HANDLER ──────────────────────────────────────────────────────
proxy.on('error', (err, req, res) => {
    console.error('[PROXY ERROR]', err.message);
    trackEvent({
        userId:     req.user?.id,
        userName:   req.user?.name,
        userRole:   req.user?.role,
        service:    req.targetService || 'unknown',
        method:     req.method,
        path:       req.url,
        statusCode: 502,
        ip:         req.ip || req.connection.remoteAddress,
        note:       `Proxy error: ${err.message}`,
    });
    res.status(502).json({ success: false, message: 'Service unavailable. Target server not reachable.' });
});

// ─── MIDDLEWARE: VERIFY JWT TOKEN ─────────────────────────────────────────────
function authToken(req, res, next) {
    const header = req?.headers.authorization;
    const token  = header && header.split(' ')[1];
    if (!token) {
        trackEvent({
            service:    req.targetService || req.path.split('/')[1] || 'gateway',
            method:     req.method,
            path:       req.path,
            statusCode: 401,
            ip:         req.ip,
            note:       'No token provided',
        });
        return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            trackEvent({
                service:    req.targetService || req.path.split('/')[1] || 'gateway',
                method:     req.method,
                path:       req.path,
                statusCode: 403,
                ip:         req.ip,
                note:       `Invalid token: ${err.message}`,
            });
            return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// ─── MIDDLEWARE: VERIFY ROLE ──────────────────────────────────────────────────
function authRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            trackEvent({
                userId:     req.user?.id,
                userName:   req.user?.name,
                userRole:   req.user?.role,
                service:    req.targetService || req.path.split('/')[1] || 'gateway',
                method:     req.method,
                path:       req.path,
                statusCode: 403,
                ip:         req.ip,
                note:       `Unauthorized role. Required: ${roles.join(' or ')}`,
            });
            return res.status(403).json({ success: false, message: `Access denied. Required role: ${roles.join(' or ')}.` });
        }
        next();
    };
}

// ─── MIDDLEWARE: REQUEST LOGGER ───────────────────────────────────────────────
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// ════════════════════════════════════════════════════════════════════════════════
//  AUTH ENDPOINTS
// ════════════════════════════════════════════════════════════════════════════════

// ─── HEALTH CHECK API ─────────────────────────────────────────────────────────
app.get('/', (req, res) => {
    res.json({ message: 'API Gateway is running', version: '1.0.0', port: 5002, timestamp: new Date().toISOString() });
});

// ─── LOGIN API ────────────────────────────────────────────────────────────────
// POST /auth/login
// Body: { email, password }
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(422).json({ success: false, message: 'email and password are required.' });
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.password === password);
    if (!user) {
        trackEvent({ service: 'auth', method: 'POST', path: '/auth/login', statusCode: 401, ip: req.ip, note: `Failed login for: ${email}` });
        return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }
    const token = jwt.sign(
        { id: user.id, name: user.name, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '1d' }
    );
    trackEvent({ userId: user.id, userName: user.name, userRole: user.role, service: 'auth', method: 'POST', path: '/auth/login', statusCode: 200, ip: req.ip, note: 'Login successful' });
    res.json({ success: true, message: 'Login successful.', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// ─── REGISTER API ─────────────────────────────────────────────────────────────
// POST /auth/register
// Body: { name, email, password, role }
app.post('/auth/register', (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password)
        return res.status(422).json({ success: false, message: 'name, email and password are required.' });
    if (!['student', 'teacher'].includes(role))
        return res.status(422).json({ success: false, message: "role must be 'student' or 'teacher'." });
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
        return res.status(409).json({ success: false, message: `Email '${email}' is already registered.` });
    const newUser = { id: users.length + 1, name, email, password, role };
    users.push(newUser);
    const token = jwt.sign(
        { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role },
        JWT_SECRET,
        { expiresIn: '1d' }
    );
    trackEvent({ userId: newUser.id, userName: newUser.name, userRole: newUser.role, service: 'auth', method: 'POST', path: '/auth/register', statusCode: 201, ip: req.ip, note: 'New user registered' });
    res.status(201).json({ success: true, message: 'Registration successful.', token, user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role } });
});

// ─── TOKEN VERIFY API ─────────────────────────────────────────────────────────
// GET /auth/verify
app.get('/auth/verify', authToken, (req, res) => {
    res.json({ success: true, message: 'Token is valid.', user: req.user });
});

// ─── GET ALL USERS API (admin only) ───────────────────────────────────────────
// GET /auth/users
app.get('/auth/users', authToken, authRole('admin'), (req, res) => {
    const safeUsers = users.map(({ password, ...u }) => u);
    res.json({ success: true, count: safeUsers.length, data: safeUsers });
});

// ════════════════════════════════════════════════════════════════════════════════
//  EVENT LOG ENDPOINTS
// ════════════════════════════════════════════════════════════════════════════════

// ─── GET ALL LOGS (admin only) ────────────────────────────────────────────────
// GET /logs
// GET /logs?service=student
// GET /logs?service=teacher
// GET /logs?role=student
// GET /logs?userId=1
// GET /logs?method=POST
// GET /logs?status=403
app.get('/logs', authToken, authRole('admin'), (req, res) => {
    let result = [...eventLogs];
    if (req.query.service) result = result.filter(l => l.service    === req.query.service.toLowerCase());
    if (req.query.role)    result = result.filter(l => l.userRole   === req.query.role.toLowerCase());
    if (req.query.userId)  result = result.filter(l => l.userId     === parseInt(req.query.userId));
    if (req.query.method)  result = result.filter(l => l.method     === req.query.method.toUpperCase());
    if (req.query.status)  result = result.filter(l => l.statusCode === parseInt(req.query.status));
    res.json({ success: true, count: result.length, data: result });
});

// ─── GET LOGS BY USER (admin only) ────────────────────────────────────────────
// GET /logs/user/1
app.get('/logs/user/:id', authToken, authRole('admin'), (req, res) => {
    const result = eventLogs.filter(l => l.userId === parseInt(req.params.id));
    res.json({ success: true, count: result.length, data: result });
});

// ─── GET LOGS BY SERVICE (admin only) ─────────────────────────────────────────
// GET /logs/service/student
// GET /logs/service/teacher
// GET /logs/service/auth
app.get('/logs/service/:name', authToken, authRole('admin'), (req, res) => {
    const result = eventLogs.filter(l => l.service === req.params.name.toLowerCase());
    res.json({ success: true, service: req.params.name, count: result.length, data: result });
});

// ─── GET LOG STATS (admin only) ───────────────────────────────────────────────
// GET /logs/stats
app.get('/logs/stats', authToken, authRole('admin'), (req, res) => {
    const total     = eventLogs.length;
    const byService = eventLogs.reduce((acc, l) => { acc[l.service]    = (acc[l.service]    || 0) + 1; return acc; }, {});
    const byRole    = eventLogs.reduce((acc, l) => { acc[l.userRole]   = (acc[l.userRole]   || 0) + 1; return acc; }, {});
    const byMethod  = eventLogs.reduce((acc, l) => { acc[l.method]     = (acc[l.method]     || 0) + 1; return acc; }, {});
    const byStatus  = eventLogs.reduce((acc, l) => { acc[l.statusCode] = (acc[l.statusCode] || 0) + 1; return acc; }, {});
    const errors    = eventLogs.filter(l => l.statusCode >= 400).length;
    const successes = eventLogs.filter(l => l.statusCode  < 400).length;
    const topUsers  = Object.entries(
        eventLogs.reduce((acc, l) => {
            if (l.userName !== 'anonymous') acc[l.userName] = (acc[l.userName] || 0) + 1;
            return acc;
        }, {})
    ).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }));

    res.json({ success: true, stats: { total, successes, errors, byService, byRole, byMethod, byStatus, topUsers } });
});

// ─── GET MY OWN LOGS (any authenticated user) ─────────────────────────────────
// GET /logs/me
app.get('/logs/me', authToken, (req, res) => {
    const result = eventLogs.filter(l => l.userId === req.user.id);
    res.json({ success: true, count: result.length, data: result });
});

// ─── CLEAR ALL LOGS (admin only) ──────────────────────────────────────────────
// DELETE /logs
app.delete('/logs', authToken, authRole('admin'), (req, res) => {
    const total = eventLogs.length;
    eventLogs   = [];
    logId       = 1;
    res.json({ success: true, message: `All ${total} logs cleared.` });
});

// ════════════════════════════════════════════════════════════════════════════════
//  PROXY ROUTES
// ════════════════════════════════════════════════════════════════════════════════

// ─── STUDENT MICROSERVICE PROXY ───────────────────────────────────────────────
// All /student/* → http://localhost:5000
// Accessible by: student, admin
app.use('/student', authToken, authRole('student', 'admin'), (req, res) => {
    req.targetService = 'student';
    proxyWithTracking(req, res, 'http://localhost:5000', 'student');
});

// ─── TEACHER MICROSERVICE PROXY ───────────────────────────────────────────────
// All /teacher/* → http://localhost:5001
// Accessible by: teacher, admin
app.use('/teacher', authToken, authRole('teacher', 'admin'), (req, res) => {
    req.targetService = 'teacher';
    proxyWithTracking(req, res, 'http://localhost:5001', 'teacher');
});

// ─── ADMIN: ACCESS BOTH SERVICES ─────────────────────────────────────────────
// All /admin/student/* → http://localhost:5000
// All /admin/teacher/* → http://localhost:5001
app.use('/admin/student', authToken, authRole('admin'), (req, res) => {
    req.targetService = 'student';
    proxyWithTracking(req, res, 'http://localhost:5000', 'student');
});

app.use('/admin/teacher', authToken, authRole('admin'), (req, res) => {
    req.targetService = 'teacher';
    proxyWithTracking(req, res, 'http://localhost:5001', 'teacher');
});

// ─── 404 HANDLER ─────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({ success: false, message: `Route ${req.method} ${req.path} not found.` });
});

// START THE EXPRESS SERVER. 5002 is the PORT NUMBER
console.clear();
app.listen(5002, () =>
    console.log('EXPRESS Server Started at Port No: 5002\nAPI Gateway is running on http://localhost:5002'));