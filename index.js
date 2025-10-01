const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = 3000;

// 미들웨어
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // index.html 제공

// 메모리 사용자 데이터 (DB 나중에 대체 가능)
let users = [];

// 루트
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 회원가입
app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const userExists = users.find(u => u.username === username);
    if (userExists) return res.status(400).json({ success: false, message: '이미 존재하는 사용자' });

    users.push({ username, password });
    console.log("✅ users:", users);
    res.status(201).json({ success: true, message: '회원가입 성공!' });
});

// 로그인
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) res.json({ success: true, message: '로그인 성공' });
    else res.status(401).json({ success: false, message: '로그인 실패' });
});

// 회원탈퇴
app.delete('/delete', (req, res) => {
    const { username } = req.body;
    const idx = users.findIndex(u => u.username === username);
    if (idx === -1) return res.status(404).json({ success: false, message: '존재하지 않는 사용자' });

    users.splice(idx, 1);
    console.log("⚠️ users after delete:", users);
    res.json({ success: true, message: '회원탈퇴 완료!' });
});

// ========================
// Socket.IO 채팅
// ========================
io.on('connection', (socket) => {
    console.log('🟢 사용자 연결됨:', socket.id);

    // 메시지 받기
    socket.on('chatMessage', ({ username, message }) => {
        if (!username || !message) return;
        console.log("💬 메시지:", username, message);
        io.emit('chatMessage', { username, message });
    });

    socket.on('disconnect', () => {
        console.log('🔴 사용자 연결 종료:', socket.id);
    });
});

// 서버 시작
server.listen(PORT, () => {
    console.log(`🌍 서버 실행중: http://localhost:${PORT}`);
});
