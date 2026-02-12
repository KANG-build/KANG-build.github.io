const express = require('express');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');
const { execSync, exec } = require('child_process');
const cors = require('cors');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

const POSTS_FILE = path.join(__dirname, '_data', 'blog', 'posts.yml');
const MEMBERS_FILE = path.join(__dirname, '_data', 'people', 'member.yml');
const ALUMNI_FILE = path.join(__dirname, '_data', 'people', 'alumni.yml');
const CATEGORIES_FILE = path.join(__dirname, '_data', 'blog', 'categories.yml');
const COMMENTS_FILE = path.join(__dirname, '_data', 'blog', 'comments.yml');
const USERS_FILE = path.join(__dirname, '_data', 'blog', 'users.yml');
const SITE_DIR = path.join(__dirname, '_site');
const UPLOAD_DIR = path.join(__dirname, 'image', 'blog');

// ==================== Security Config ====================
// Generate a random secret on each server start for extra safety
// In production, use an env var: process.env.JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '7d';
const BCRYPT_ROUNDS = 12;
const COOKIE_NAME = '__srclab_sess';
const COOKIE_OPTIONS = {
    httpOnly: true,       // JS cannot read it -> no XSS cookie theft
    secure: false,        // set true in production with HTTPS
    sameSite: 'lax',      // CSRF protection
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/'
};

// ==================== Kakao OAuth Config ====================
// Set these env vars or replace the defaults with your Kakao app credentials
// 1. Go to https://developers.kakao.com → My Application → Create App
// 2. In "Kakao Login" settings, add your redirect URI
// 3. Copy "REST API Key" from App Keys → paste as KAKAO_CLIENT_ID
// 4. In "Security" tab → generate Client Secret → paste as KAKAO_CLIENT_SECRET
const KAKAO_CLIENT_ID = process.env.KAKAO_CLIENT_ID || '';     // REST API Key
const KAKAO_CLIENT_SECRET = process.env.KAKAO_CLIENT_SECRET || ''; // Client Secret (optional but recommended)
const KAKAO_REDIRECT_URI = process.env.KAKAO_REDIRECT_URI || ''; // e.g. https://yourdomain.com/api/auth/kakao/callback
// OAuth state parameter secret for CSRF protection
const OAUTH_STATE_SECRET = crypto.randomBytes(32).toString('hex');

// ==================== Cookie Parser (minimal, no dependency) ====================
function parseCookies(req) {
    const cookies = {};
    const header = req.headers.cookie;
    if (!header) return cookies;
    header.split(';').forEach(function(c) {
        const parts = c.split('=');
        const key = parts[0].trim();
        const val = parts.slice(1).join('=').trim();
        cookies[key] = decodeURIComponent(val);
    });
    return cookies;
}

// ==================== KST Date Helper ====================
function getKSTDate() {
    const now = new Date();
    const kst = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    return kst.toISOString().split('T')[0];
}

function getKSTTimestamp() {
    const now = new Date();
    const kst = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    return kst.toISOString().replace('Z', '+09:00');
}

// Multer setup for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname) || '.png';
        const name = Date.now() + '-' + Math.random().toString(36).substring(2, 8) + ext;
        cb(null, name);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = /\.(jpg|jpeg|png|gif|webp|svg|bmp)$/i;
        if (allowed.test(path.extname(file.originalname))) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// ==================== Data Helpers ====================
function readPosts() {
    try { return yaml.load(fs.readFileSync(POSTS_FILE, 'utf8')) || []; } catch (e) { return []; }
}
function writePosts(posts) {
    fs.writeFileSync(POSTS_FILE, yaml.dump(posts, { lineWidth: -1, noRefs: true, quotingType: '"', forceQuotes: false }), 'utf8');
}
function readMembers() {
    try { return yaml.load(fs.readFileSync(MEMBERS_FILE, 'utf8')) || []; } catch (e) { return []; }
}
function writeMembers(members) {
    fs.writeFileSync(MEMBERS_FILE, yaml.dump(members, { lineWidth: -1, noRefs: true, quotingType: '"', forceQuotes: false }), 'utf8');
}
function readAlumni() {
    try { return yaml.load(fs.readFileSync(ALUMNI_FILE, 'utf8')) || []; } catch (e) { return []; }
}
function writeAlumni(alumni) {
    fs.writeFileSync(ALUMNI_FILE, yaml.dump(alumni, { lineWidth: -1, noRefs: true, quotingType: '"', forceQuotes: false }), 'utf8');
}
function readCategories() {
    try { return yaml.load(fs.readFileSync(CATEGORIES_FILE, 'utf8')) || []; } catch (e) { return []; }
}
function readComments() {
    try { return yaml.load(fs.readFileSync(COMMENTS_FILE, 'utf8')) || []; } catch (e) { return []; }
}
function writeComments(comments) {
    fs.writeFileSync(COMMENTS_FILE, yaml.dump(comments, { lineWidth: -1, noRefs: true, quotingType: '"', forceQuotes: false }), 'utf8');
}
function readUsers() {
    try { return yaml.load(fs.readFileSync(USERS_FILE, 'utf8')) || []; } catch (e) { return []; }
}
function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, yaml.dump(users, { lineWidth: -1, noRefs: true, quotingType: '"', forceQuotes: false }), 'utf8');
}

function generatePostId(posts) {
    let maxNum = 0;
    posts.forEach(p => { const m = p.id && p.id.match(/post-(\d+)/); if (m) { const n = parseInt(m[1]); if (n > maxNum) maxNum = n; } });
    return 'post-' + String(maxNum + 1).padStart(3, '0');
}
function generateCommentId(comments) {
    let maxNum = 0;
    comments.forEach(c => { const m = c.id && c.id.match(/cmt-(\d+)/); if (m) { const n = parseInt(m[1]); if (n > maxNum) maxNum = n; } });
    return 'cmt-' + String(maxNum + 1).padStart(4, '0');
}

function rebuildJekyll() {
    return new Promise((resolve, reject) => {
        exec('cd ' + __dirname + ' && jekyll build', { timeout: 30000 }, (err, stdout, stderr) => {
            if (err) { console.error('Jekyll build error:', stderr); reject(err); }
            else { console.log('Jekyll rebuilt successfully'); resolve(stdout); }
        });
    });
}

// ==================== Auth Helpers ====================
function getMemberList() {
    return readMembers()
        .filter(m => m.name !== 'Join us!')
        .map(m => ({
            name: m.name,
            id: m.name.replace(/\s+/g, '').toLowerCase(),
            photo: m.photo,
            role: m.role || '',
            email: m.email || ''
        }));
}

function isMemberId(id) {
    return getMemberList().some(m => m.id === id);
}

function createToken(user) {
    return jwt.sign(
        { uid: user.id, name: user.display_name, member_id: user.member_id || null, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

function verifyToken(token) {
    try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}

// Middleware: extract user from httpOnly cookie (optional - doesn't block)
function authOptional(req, res, next) {
    const cookies = parseCookies(req);
    const token = cookies[COOKIE_NAME];
    if (token) {
        const decoded = verifyToken(token);
        if (decoded) req.user = decoded;
    }
    next();
}

// Middleware: require logged-in member (lab member only)
function requireMember(req, res, next) {
    const cookies = parseCookies(req);
    const token = cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: '세션이 만료되었습니다. 다시 로그인해주세요.' });
    if (decoded.role !== 'member') return res.status(403).json({ error: '연구실 멤버만 가능합니다.' });
    req.user = decoded;
    next();
}

// Middleware: require any logged-in user
function requireLogin(req, res, next) {
    const cookies = parseCookies(req);
    const token = cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: '세션이 만료되었습니다.' });
    req.user = decoded;
    next();
}

// ==================== Auth API ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, display_name, member_id } = req.body;
        if (!username || !password || !display_name) {
            return res.status(400).json({ error: '아이디, 비밀번호, 표시 이름은 필수입니다.' });
        }
        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({ error: '아이디는 3~30자여야 합니다.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });
        }
        // Sanitize username: only alphanumeric and underscore
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: '아이디는 영문, 숫자, 밑줄(_)만 사용 가능합니다.' });
        }

        const users = readUsers();
        if (users.find(u => u.username === username.toLowerCase())) {
            return res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });
        }

        // Determine role: if member_id matches a lab member, role = 'member'
        let role = 'guest';
        let validMemberId = null;
        if (member_id) {
            const members = getMemberList();
            const found = members.find(m => m.id === member_id);
            if (found) {
                // Check no other user already claimed this member_id
                if (users.find(u => u.member_id === member_id)) {
                    return res.status(409).json({ error: '이 멤버 계정은 이미 등록되어 있습니다.' });
                }
                role = 'member';
                validMemberId = member_id;
            }
        }

        const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const newUser = {
            id: 'user-' + Date.now().toString(36),
            username: username.toLowerCase(),
            password_hash: hash,
            display_name: display_name,
            member_id: validMemberId,
            role: role,
            created_at: getKSTTimestamp()
        };
        users.push(newUser);
        writeUsers(users);

        // Auto-login after register
        const token = createToken(newUser);
        res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7*24*60*60}`);
        res.json({
            success: true,
            user: { id: newUser.id, username: newUser.username, display_name: newUser.display_name, member_id: newUser.member_id, role: newUser.role }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
        }
        const users = readUsers();
        const user = users.find(u => u.username === username.toLowerCase());
        if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

        // Kakao-only users can't login with password
        if (!user.password_hash && user.auth_provider === 'kakao') {
            return res.status(401).json({ error: '카카오로 가입된 계정입니다. 카카오 로그인을 이용해주세요.' });
        }

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

        const token = createToken(user);
        res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7*24*60*60}`);
        res.json({
            success: true,
            user: { id: user.id, username: user.username, display_name: user.display_name, member_id: user.member_id, role: user.role }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    res.json({ success: true });
});

// Get current session
app.get('/api/auth/me', (req, res) => {
    const cookies = parseCookies(req);
    const token = cookies[COOKIE_NAME];
    if (!token) return res.json({ logged_in: false });
    const decoded = verifyToken(token);
    if (!decoded) return res.json({ logged_in: false });

    // Get photo if member
    let photo = '/image/people/empty.png';
    if (decoded.member_id) {
        const members = getMemberList();
        const m = members.find(x => x.id === decoded.member_id);
        if (m) photo = m.photo;
    }

    // For Kakao users without member link, use Kakao photo
    let authProvider = null;
    const users = readUsers();
    const fullUser = users.find(u => u.id === decoded.uid);
    if (fullUser) {
        if (!decoded.member_id && fullUser.kakao_photo) {
            photo = fullUser.kakao_photo;
        }
        authProvider = fullUser.auth_provider || 'local';
    }

    res.json({
        logged_in: true,
        user: {
            id: decoded.uid,
            name: decoded.name,
            member_id: decoded.member_id,
            role: decoded.role,
            photo: photo,
            auth_provider: authProvider
        }
    });
});

// Get list of member_ids already claimed by users (for UI to disable them)
app.get('/api/auth/claimed-members', (req, res) => {
    const users = readUsers();
    const claimed = users.filter(u => u.member_id).map(u => u.member_id);
    res.json({ claimed: claimed });
});

// ==================== Profile / My Page API ====================

// Change username
app.post('/api/auth/change-username', requireLogin, async (req, res) => {
    try {
        const { new_username } = req.body;
        if (!new_username) return res.status(400).json({ error: '새 아이디를 입력해주세요.' });
        const trimmed = new_username.trim().toLowerCase();
        if (trimmed.length < 3 || trimmed.length > 30) {
            return res.status(400).json({ error: '아이디는 3~30자여야 합니다.' });
        }
        if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
            return res.status(400).json({ error: '아이디는 영문, 숫자, 밑줄(_)만 사용 가능합니다.' });
        }

        const users = readUsers();
        const userIdx = users.findIndex(u => u.id === req.user.uid);
        if (userIdx === -1) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

        // Check not same as current
        if (users[userIdx].username === trimmed) {
            return res.status(400).json({ error: '현재와 동일한 아이디입니다.' });
        }

        // Check uniqueness
        if (users.find(u => u.username === trimmed && u.id !== req.user.uid)) {
            return res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });
        }

        users[userIdx].username = trimmed;
        writeUsers(users);

        res.json({ success: true, username: trimmed });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// Change password
app.post('/api/auth/change-password', requireLogin, async (req, res) => {
    try {
        const { current_password, new_password } = req.body;
        if (!new_password) return res.status(400).json({ error: '새 비밀번호를 입력해주세요.' });
        if (new_password.length < 6) return res.status(400).json({ error: '비밀번호는 6자 이상이어야 합니다.' });

        const users = readUsers();
        const userIdx = users.findIndex(u => u.id === req.user.uid);
        if (userIdx === -1) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

        const user = users[userIdx];

        // If user has a password (local or hybrid), verify current password
        if (user.password_hash) {
            if (!current_password) return res.status(400).json({ error: '현재 비밀번호를 입력해주세요.' });
            const valid = await bcrypt.compare(current_password, user.password_hash);
            if (!valid) return res.status(401).json({ error: '현재 비밀번호가 틀렸습니다.' });
        }
        // Kakao-only users can set a password without current_password check

        const hash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
        users[userIdx].password_hash = hash;
        writeUsers(users);

        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// Change display name
app.post('/api/auth/change-displayname', requireLogin, (req, res) => {
    try {
        const { new_display_name } = req.body;
        if (!new_display_name || !new_display_name.trim()) {
            return res.status(400).json({ error: '표시 이름을 입력해주세요.' });
        }
        const trimmed = new_display_name.trim();
        if (trimmed.length > 50) return res.status(400).json({ error: '표시 이름은 50자 이하여야 합니다.' });

        const users = readUsers();
        const userIdx = users.findIndex(u => u.id === req.user.uid);
        if (userIdx === -1) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

        users[userIdx].display_name = trimmed;
        writeUsers(users);

        // Reissue token with new name
        const newToken = createToken(users[userIdx]);
        res.setHeader('Set-Cookie', `${COOKIE_NAME}=${newToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7*24*60*60}`);

        res.json({ success: true, display_name: trimmed });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// Get full profile info for my page
app.get('/api/auth/profile', requireLogin, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.id === req.user.uid);
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

    let photo = '/image/people/empty.png';
    let memberName = null;
    if (user.member_id) {
        const members = getMemberList();
        const m = members.find(x => x.id === user.member_id);
        if (m) { photo = m.photo; memberName = m.name; }
    } else if (user.kakao_photo) {
        photo = user.kakao_photo;
    }

    res.json({
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        member_id: user.member_id,
        member_name: memberName,
        role: user.role,
        photo: photo,
        auth_provider: user.auth_provider || 'local',
        has_password: !!user.password_hash,
        kakao_email: user.kakao_email || null,
        created_at: user.created_at
    });
});

// ==================== Kakao OAuth API ====================

// Helper: generate signed state parameter (CSRF protection)
function generateOAuthState() {
    const nonce = crypto.randomBytes(16).toString('hex');
    const ts = Date.now();
    const payload = nonce + '|' + ts;
    const hmac = crypto.createHmac('sha256', OAUTH_STATE_SECRET).update(payload).digest('hex');
    return payload + '|' + hmac;
}

// Helper: verify state parameter
function verifyOAuthState(state) {
    if (!state) return false;
    const parts = state.split('|');
    if (parts.length !== 3) return false;
    const [nonce, ts, hmac] = parts;
    // Check expiry (10 minutes)
    if (Date.now() - parseInt(ts) > 10 * 60 * 1000) return false;
    const expected = crypto.createHmac('sha256', OAUTH_STATE_SECRET).update(nonce + '|' + ts).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(expected, 'hex'));
}

// Check if Kakao is configured
app.get('/api/auth/kakao/status', (req, res) => {
    res.json({ enabled: !!(KAKAO_CLIENT_ID && KAKAO_REDIRECT_URI) });
});

// Step 1: Redirect to Kakao authorize page
app.get('/api/auth/kakao/login', (req, res) => {
    if (!KAKAO_CLIENT_ID || !KAKAO_REDIRECT_URI) {
        return res.status(503).json({ error: '카카오 로그인이 아직 설정되지 않았습니다. 관리자에게 문의하세요.' });
    }
    const state = generateOAuthState();
    const redirect = req.query.redirect || '/pages/blog.html';
    // Store redirect in a temporary httpOnly cookie
    res.setHeader('Set-Cookie', [
        `__srclab_oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
        `__srclab_oauth_redirect=${encodeURIComponent(redirect)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`
    ]);
    const kakaoAuthUrl = 'https://kauth.kakao.com/oauth/authorize' +
        '?client_id=' + KAKAO_CLIENT_ID +
        '&redirect_uri=' + encodeURIComponent(KAKAO_REDIRECT_URI) +
        '&response_type=code' +
        '&state=' + encodeURIComponent(state) +
        '&scope=profile_nickname,profile_image,account_email';
    res.redirect(kakaoAuthUrl);
});

// Step 2: Kakao callback — exchange code for token, get user info, create/login user
app.get('/api/auth/kakao/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;

        if (error) {
            console.error('Kakao OAuth error:', error, error_description);
            return res.redirect('/pages/login.html?error=' + encodeURIComponent(error_description || '카카오 로그인이 취소되었습니다.'));
        }

        if (!code) {
            return res.redirect('/pages/login.html?error=' + encodeURIComponent('인증 코드가 없습니다.'));
        }

        // Verify state (CSRF protection)
        const cookies = parseCookies(req);
        const savedState = cookies['__srclab_oauth_state'];
        if (!savedState || savedState !== state || !verifyOAuthState(state)) {
            return res.redirect('/pages/login.html?error=' + encodeURIComponent('보안 검증 실패. 다시 시도해주세요.'));
        }

        const savedRedirect = cookies['__srclab_oauth_redirect'] ? decodeURIComponent(cookies['__srclab_oauth_redirect']) : '/pages/blog.html';

        // Exchange authorization code for access token
        const tokenParams = new URLSearchParams();
        tokenParams.append('grant_type', 'authorization_code');
        tokenParams.append('client_id', KAKAO_CLIENT_ID);
        tokenParams.append('redirect_uri', KAKAO_REDIRECT_URI);
        tokenParams.append('code', code);
        if (KAKAO_CLIENT_SECRET) {
            tokenParams.append('client_secret', KAKAO_CLIENT_SECRET);
        }

        const tokenResponse = await fetch('https://kauth.kakao.com/oauth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8' },
            body: tokenParams.toString()
        });
        const tokenData = await tokenResponse.json();

        if (tokenData.error) {
            console.error('Kakao token error:', tokenData);
            return res.redirect('/pages/login.html?error=' + encodeURIComponent('카카오 토큰 발급 실패: ' + (tokenData.error_description || tokenData.error)));
        }

        const accessToken = tokenData.access_token;

        // Get user info from Kakao
        const userResponse = await fetch('https://kapi.kakao.com/v2/user/me', {
            headers: { 'Authorization': 'Bearer ' + accessToken }
        });
        const kakaoUser = await userResponse.json();

        if (!kakaoUser.id) {
            return res.redirect('/pages/login.html?error=' + encodeURIComponent('카카오 사용자 정보를 가져올 수 없습니다.'));
        }

        const kakaoId = String(kakaoUser.id);
        const kakaoAccount = kakaoUser.kakao_account || {};
        const kakaoProfile = kakaoAccount.profile || {};
        const kakaoNickname = kakaoProfile.nickname || '카카오사용자';
        const kakaoProfileImage = kakaoProfile.profile_image_url || null;
        const kakaoEmail = kakaoAccount.email || null;

        // Disconnect the Kakao token (we don't store it — security best practice)
        // We only need it temporarily to get user info
        fetch('https://kapi.kakao.com/v1/user/unlink', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + accessToken }
        }).catch(() => {}); // fire and forget - we don't need to keep the token linked

        // Find or create user in our system
        const users = readUsers();
        let user = users.find(u => u.kakao_id === kakaoId);

        if (user) {
            // Existing Kakao user — update profile info
            user.display_name = kakaoNickname;
            if (kakaoProfileImage) user.kakao_photo = kakaoProfileImage;
            if (kakaoEmail) user.kakao_email = kakaoEmail;
            user.last_login = getKSTTimestamp();
            writeUsers(users);
        } else {
            // New Kakao user — create account
            user = {
                id: 'user-' + Date.now().toString(36),
                username: 'kakao_' + kakaoId,
                password_hash: null, // No password for social login
                display_name: kakaoNickname,
                member_id: null,
                role: 'guest',
                kakao_id: kakaoId,
                kakao_photo: kakaoProfileImage,
                kakao_email: kakaoEmail,
                auth_provider: 'kakao',
                created_at: getKSTTimestamp(),
                last_login: getKSTTimestamp()
            };
            users.push(user);
            writeUsers(users);
        }

        // Issue JWT session cookie
        const token = createToken(user);

        // Clear OAuth temp cookies and set session cookie
        res.setHeader('Set-Cookie', [
            `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7*24*60*60}`,
            `__srclab_oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
            `__srclab_oauth_redirect=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
        ]);

        // If the user hasn't linked a member yet and they're new, redirect to link page
        if (!user.member_id && !user.password_hash) {
            // New social login user — optionally redirect to member linking page
            return res.redirect('/pages/login.html?kakao_link=true&redirect=' + encodeURIComponent(savedRedirect));
        }

        res.redirect(savedRedirect);
    } catch (e) {
        console.error('Kakao callback error:', e);
        res.redirect('/pages/login.html?error=' + encodeURIComponent('서버 오류가 발생했습니다.'));
    }
});

// Link Kakao account to a lab member (optional, after Kakao login)
app.post('/api/auth/kakao/link-member', requireLogin, (req, res) => {
    try {
        const { member_id } = req.body;
        if (!member_id) {
            return res.json({ success: true, message: '멤버 연동 없이 진행합니다.' });
        }

        const members = getMemberList();
        const found = members.find(m => m.id === member_id);
        if (!found) {
            return res.status(400).json({ error: '존재하지 않는 멤버입니다.' });
        }

        const users = readUsers();
        // Check if another user already claimed this member_id
        if (users.find(u => u.member_id === member_id && u.id !== req.user.uid)) {
            return res.status(409).json({ error: '이 멤버 계정은 이미 다른 사용자에게 연동되어 있습니다.' });
        }

        const userIdx = users.findIndex(u => u.id === req.user.uid);
        if (userIdx === -1) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

        users[userIdx].member_id = member_id;
        users[userIdx].role = 'member';
        writeUsers(users);

        // Reissue token with updated role
        const newToken = createToken(users[userIdx]);
        res.setHeader('Set-Cookie', `${COOKIE_NAME}=${newToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7*24*60*60}`);

        res.json({
            success: true,
            user: {
                id: users[userIdx].id,
                display_name: users[userIdx].display_name,
                member_id: users[userIdx].member_id,
                role: users[userIdx].role
            }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

// ==================== Image Upload API ====================
app.post('/api/upload', requireMember, (req, res) => {
    upload.single('image')(req, res, (err) => {
        if (err) {
            if (err instanceof multer.MulterError) {
                if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 10MB)' });
                return res.status(400).json({ error: err.message });
            }
            return res.status(400).json({ error: err.message || 'Upload failed' });
        }
        if (!req.file) return res.status(400).json({ error: 'No image file provided' });
        const url = '/image/blog/' + req.file.filename;
        const siteImgDir = path.join(SITE_DIR, 'image', 'blog');
        if (!fs.existsSync(siteImgDir)) fs.mkdirSync(siteImgDir, { recursive: true });
        fs.copyFileSync(req.file.path, path.join(siteImgDir, req.file.filename));
        res.json({ success: true, url: url, filename: req.file.filename });
    });
});

// ==================== Public API Routes ====================
app.get('/api/members', (req, res) => { res.json(getMemberList()); });
app.get('/api/categories', (req, res) => { res.json(readCategories()); });
app.get('/api/posts', (req, res) => { res.json(readPosts()); });
app.get('/api/posts/:id', (req, res) => {
    const posts = readPosts();
    const post = posts.find(p => p.id === req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    res.json(post);
});

// ==================== Protected Post Routes (member only) ====================
app.post('/api/posts', requireMember, async (req, res) => {
    try {
        const { title, category, tags, summary, content } = req.body;
        if (!title || !content) {
            return res.status(400).json({ error: 'title and content are required' });
        }
        // Author is the logged-in member
        const members = getMemberList();
        const member = members.find(m => m.id === req.user.member_id);
        if (!member) return res.status(403).json({ error: 'Member data not found' });

        const posts = readPosts();
        const newPost = {
            id: generatePostId(posts),
            title,
            author: member.name,
            author_id: member.id,
            date: getKSTDate(),
            category: category || 'Dev Log',
            tags: tags || [],
            summary: summary || title,
            content
        };
        posts.unshift(newPost);
        writePosts(posts);
        await rebuildJekyll();
        res.json({ success: true, post: newPost });
    } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.put('/api/posts/:id', requireMember, async (req, res) => {
    try {
        const { title, category, tags, summary, content } = req.body;
        const posts = readPosts();
        const idx = posts.findIndex(p => p.id === req.params.id);
        if (idx === -1) return res.status(404).json({ error: 'Post not found' });
        // Only the author or any member can edit
        if (title) posts[idx].title = title;
        if (category) posts[idx].category = category;
        if (tags) posts[idx].tags = tags;
        if (summary !== undefined) posts[idx].summary = summary;
        if (content !== undefined) posts[idx].content = content;
        posts[idx].date = getKSTDate();
        writePosts(posts);
        await rebuildJekyll();
        res.json({ success: true, post: posts[idx] });
    } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.delete('/api/posts/:id', requireMember, async (req, res) => {
    try {
        const posts = readPosts();
        const idx = posts.findIndex(p => p.id === req.params.id);
        if (idx === -1) return res.status(404).json({ error: 'Post not found' });
        const deleted = posts.splice(idx, 1)[0];
        writePosts(posts);
        let comments = readComments();
        comments = comments.filter(c => c.post_id !== deleted.id);
        writeComments(comments);
        await rebuildJekyll();
        res.json({ success: true, deleted: deleted.id });
    } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ==================== Comments API ====================
app.get('/api/posts/:id/comments', (req, res) => {
    const comments = readComments();
    const postComments = comments.filter(c => c.post_id === req.params.id).sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    res.json(postComments);
});

// Add comment - anyone can comment, but we tag whether they're logged in
app.post('/api/posts/:id/comments', authOptional, (req, res) => {
    try {
        const { author, author_id, content, parent_id } = req.body;
        if (!content) return res.status(400).json({ error: 'content is required' });
        const posts = readPosts();
        if (!posts.find(p => p.id === req.params.id)) return res.status(404).json({ error: 'Post not found' });
        const comments = readComments();
        if (parent_id) {
            if (!comments.find(c => c.id === parent_id)) return res.status(404).json({ error: 'Parent comment not found' });
        }

        // Determine author info
        let commentAuthor, commentAuthorId, isLoggedIn = false, isMember = false;
        if (req.user) {
            // Logged in user
            isLoggedIn = true;
            commentAuthor = req.user.name;
            commentAuthorId = req.user.member_id || req.user.uid;
            isMember = req.user.role === 'member';
        } else {
            // Anonymous
            if (!author) return res.status(400).json({ error: 'author is required for anonymous comments' });
            commentAuthor = author;
            commentAuthorId = author_id || author.replace(/\s+/g, '').toLowerCase();
        }

        const newComment = {
            id: generateCommentId(comments),
            post_id: req.params.id,
            parent_id: parent_id || null,
            author: commentAuthor,
            author_id: commentAuthorId,
            is_member: isMember,
            is_logged_in: isLoggedIn,
            content,
            created_at: getKSTTimestamp()
        };
        comments.push(newComment);
        writeComments(comments);
        res.json({ success: true, comment: newComment });
    } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// Delete comment - author or any member can delete
app.delete('/api/comments/:id', authOptional, (req, res) => {
    try {
        let comments = readComments();
        const idx = comments.findIndex(c => c.id === req.params.id);
        if (idx === -1) return res.status(404).json({ error: 'Comment not found' });
        const comment = comments[idx];

        // Permission check: comment owner or logged-in member
        const canDelete = (req.user && (
            req.user.role === 'member' ||
            req.user.uid === comment.author_id ||
            req.user.member_id === comment.author_id
        ));
        if (!canDelete) return res.status(403).json({ error: '삭제 권한이 없습니다.' });

        const deletedId = comments[idx].id;
        comments = comments.filter(c => c.id !== deletedId && c.parent_id !== deletedId);
        writeComments(comments);
        res.json({ success: true, deleted: deletedId });
    } catch (e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ==================== Member Management API ====================
app.post('/api/members/move-to-alumni', requireMember, async (req, res) => {
    try {
        const { memberName } = req.body;
        if (!memberName) {
            return res.status(400).json({ error: 'memberName is required' });
        }

        // Read current members and alumni
        const members = readMembers();
        const alumni = readAlumni();

        // Find the member to move
        const memberIndex = members.findIndex(m => m.name === memberName);
        if (memberIndex === -1) {
            return res.status(404).json({ error: 'Member not found' });
        }

        // Prevent moving "Join us!" placeholder
        if (memberName === 'Join us!') {
            return res.status(400).json({ error: 'Cannot move "Join us!" to alumni' });
        }

        // Remove from members and add to alumni
        const memberToMove = members[memberIndex];
        members.splice(memberIndex, 1);

        // Add to alumni (keep only name and photo for alumni)
        const alumniEntry = {
            name: memberToMove.name,
            photo: memberToMove.photo
        };
        if (memberToMove.link) {
            alumniEntry.link = memberToMove.link;
        }
        alumni.push(alumniEntry);

        // Write back to files
        writeMembers(members);
        writeAlumni(alumni);

        // Rebuild Jekyll site
        await rebuildJekyll();

        res.json({ 
            success: true, 
            message: `${memberName} moved to alumni`,
            member: alumniEntry
        });
    } catch (e) { 
        console.error(e); 
        res.status(500).json({ error: e.message }); 
    }
});

app.post('/api/members/move-to-members', requireMember, async (req, res) => {
    try {
        const { memberName, role, email } = req.body;
        if (!memberName) {
            return res.status(400).json({ error: 'memberName is required' });
        }

        // Read current members and alumni
        const members = readMembers();
        const alumni = readAlumni();

        // Find the alumni member to move
        const alumniIndex = alumni.findIndex(a => a.name === memberName);
        if (alumniIndex === -1) {
            return res.status(404).json({ error: 'Alumni member not found' });
        }

        // Remove from alumni and add to members
        const alumniToMove = alumni[alumniIndex];
        alumni.splice(alumniIndex, 1);

        // Add to members with role and email
        const memberEntry = {
            name: alumniToMove.name,
            photo: alumniToMove.photo,
            role: role || 'Member',
            email: email || ''
        };
        if (alumniToMove.link) {
            memberEntry.link = alumniToMove.link;
        }
        members.push(memberEntry);

        // Write back to files
        writeMembers(members);
        writeAlumni(alumni);

        // Rebuild Jekyll site
        await rebuildJekyll();

        res.json({ 
            success: true, 
            message: `${memberName} moved to members`,
            member: memberEntry
        });
    } catch (e) { 
        console.error(e); 
        res.status(500).json({ error: e.message }); 
    }
});

// ==================== Static Files ====================
app.use('/image/blog', express.static(UPLOAD_DIR));
app.use(express.static(SITE_DIR));

app.use((req, res) => {
    const filePath = path.join(SITE_DIR, req.path);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        res.sendFile(filePath);
    } else if (fs.existsSync(filePath + '.html')) {
        res.sendFile(filePath + '.html');
    } else if (fs.existsSync(path.join(filePath, 'index.html'))) {
        res.sendFile(path.join(filePath, 'index.html'));
    } else {
        res.sendFile(path.join(SITE_DIR, 'index.html'));
    }
});

// ==================== Start ====================
const PORT = 4000;

// Initialize data files
[COMMENTS_FILE, USERS_FILE].forEach(f => {
    if (!fs.existsSync(f)) fs.writeFileSync(f, '[]', 'utf8');
});

console.log('Building Jekyll site...');
try {
    execSync('cd ' + __dirname + ' && jekyll build', { stdio: 'inherit' });
    console.log('Jekyll build complete!');
} catch (e) {
    console.error('Initial Jekyll build failed:', e.message);
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n Blog API running on http://0.0.0.0:${PORT}`);
    console.log(` KST Date: ${getKSTDate()}`);
    console.log(` Auth: JWT httpOnly cookie, bcrypt ${BCRYPT_ROUNDS} rounds`);
});
