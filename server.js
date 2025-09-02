// 필요한 모듈 불러오기
require("dotenv").config(); // .env 파일의 환경 변수를 불러옴

const express = require("express");
const sql = require("mssql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors"); //
const nodemailer = require('nodemailer');
const port = process.env.SERVER_PORT || 3000; // 환경 변수에서 포트를 가져오고, 없으면 3000번 사용
const app = express();
const verificationCodes = {}; // { email: '123456', expires: ... }

// 🔻 미들웨어 설정
app.use(cors()); // CORS 허용
app.use(express.json()); // express 내장 body-parser 사용

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,       // .env 파일의 Gmail 주소
        pass: process.env.GMAIL_APP_PASSWORD // .env 파일의 Gmail 앱 비밀번호
    }
});

// 🔹 SQL Server 연결 설정
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        encrypt: false,
        trustServerCertificate: true, // 개발용으로는 true, 배포 시에는 false 권장
    },
};

// 🔹 데이터베이스 연결 확인 함수
async function checkDbConnection() {
    try {
        await sql.connect(dbConfig);
        console.log("✅ SQL Server에 성공적으로 연결되었습니다.");
    } catch (err) {
        console.error("❌ SQL Server 연결 실패:", err);
        process.exit(1); // 연결 실패 시 서버 종료
    }
}

// 🔹 JWT 시크릿 키
const JWT_SECRET = process.env.JWT_SECRET;

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN" 형식

    if (token == null) return res.sendStatus(401); // 토큰이 없음

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // 토큰이 유효하지 않음
        req.user = user; // 요청 객체에 사용자 정보(id, username)를 저장
        next(); // 다음 미들웨어나 API 로직으로 진행
    });
};

// ------------------------
// API Endpoints
// ------------------------

/**
 * 헬스 체크 API
 * 서버가 살아있는지 확인하는 용도
 */
app.get("/", (req, res) => {
    res.send("계정 서버가 정상적으로 동작하고 있습니다.");
});


/**
 * 회원가입 API
 */
app.post("/register", async (req, res) => {
    const { username, password, email, nickname } = req.body;

    // 1. 입력값 검증
    if (!username || !password || !email || !nickname) {
        return res.status(400).json({ success: false, message: "모든 필드를 입력해주세요." });
    }

    try {
        const pool = await sql.connect(dbConfig);

        // 2. 아이디 중복 체크
        const userExists = await pool.request()
            .input("username", sql.NVarChar, username)
            .query("SELECT Username FROM Accounts WHERE Username = @username");

        if (userExists.recordset.length > 0) {
            return res.status(400).json({ success: false, message: "이미 존재하는 아이디입니다." });
        }

        // 3. 닉네임 중복 체크
        const nicknameExists = await pool.request()
            .input("nickname", sql.NVarChar, nickname)
            .query("SELECT Nickname FROM Accounts WHERE Nickname = @nickname");

        if (nicknameExists.recordset.length > 0) {
            return res.status(400).json({ success: false, message: "이미 존재하는 닉네임입니다." });
        }

        // ▼▼▼ 이메일 중복 체크 로직 추가 ▼▼▼
        // 4. 이메일 중복 체크
        const emailExists = await pool.request()
            .input("email", sql.NVarChar, email)
            .query("SELECT Email FROM Accounts WHERE Email = @email");

        if (emailExists.recordset.length > 0) {
            return res.status(400).json({ success: false, message: "이미 사용 중인 이메일입니다." });
        }
        // ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

        // 5. 비밀번호 해싱
        const hashedPassword = await bcrypt.hash(password, 10);

        // 6. 계정 삽입
        await pool.request()
            .input("username", sql.NVarChar, username)
            .input("passwordHash", sql.NVarChar, hashedPassword)
            .input("email", sql.NVarChar, email)
            .input("nickname", sql.NVarChar, nickname)
            .query(
                `INSERT INTO Accounts (Username, PasswordHash, Email, Nickname)
                 VALUES (@username, @passwordHash, @email, @nickname)`
            );

        res.status(201).json({ success: true, message: "회원가입 성공" });

    } catch (err) {
        console.error("회원가입 서버 오류:", err);
        res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
});
/**
 * 아이디 중복 확인 API
 */
app.post("/check-username", async (req, res) => {
    const { username } = req.body;
    if (!username) {
        // 'return'으로 함수를 확실히 종료
        return res.status(400).json({ success: false, message: "아이디를 입력해주세요." });
    }

    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input("username", sql.NVarChar, username)
            .query("SELECT Username FROM Accounts WHERE Username = @username");

        if (result.recordset.length > 0) {
            // 중복 시 JSON 응답 후 'return'으로 종료
            return res.status(400).json({ success: false, message: "이미 존재하는 아이디입니다." });
        } else {
            // 성공 시 JSON 응답 후 'return'으로 종료
            return res.json({ success: true, message: "사용 가능한 아이디입니다." });
        }
    } catch (err) {
        console.error("아이디 중복 확인 오류:", err);
        // 에러 발생 시에도 JSON 응답 후 'return'으로 종료
        return res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
});

/**
 * 로그인 API
 */
app.post("/login", async (req, res) => {
    const { userId, userPassword } = req.body; // 🔻 유니티 C# 스크립트의 변수명(userId, userPassword)과 일치시킴

    // 🔻 1. 입력값 검증
    if (!userId || !userPassword) {
        return res.status(400).json({ success: false, message: "아이디와 비밀번호를 입력해주세요." });
    }

    try {
        const pool = await sql.connect(dbConfig);

        // 2. 계정 확인
        const result = await pool.request()
            .input("username", sql.NVarChar, userId) // 🔻 userId로 변경
            .query("SELECT * FROM Accounts WHERE Username = @username");

        if (result.recordset.length === 0) {
            return res.status(400).json({ success: false, message: "아이디 또는 비밀번호가 올바르지 않습니다." });
        }

        const user = result.recordset[0];

        // 3. 비밀번호 검증
        const isMatch = await bcrypt.compare(userPassword, user.PasswordHash); // 🔻 userPassword로 변경
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "아이디 또는 비밀번호가 올바르지 않습니다." });
        }

        // 4. JWT 토큰 발급
        const token = jwt.sign(
            { id: user.AccountID, username: user.Username },
            JWT_SECRET,
            { expiresIn: "1h" } // 토큰 유효기간 1시간
        );

        res.json({ success: true, message: "로그인 성공", token: token });

    } catch (err) {
        console.error("로그인 서버 오류:", err);
        res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
});

// ------------------------
// 서버 시작
// ------------------------
app.listen(port, async () => {
    await checkDbConnection(); // 서버 시작 전 DB 연결 확인
    console.log(`🚀 계정 서버 실행 중 (http://localhost:${port})`);
});

/**
 * 회원가입 이메일 인증번호 발송 API
 */
app.post("/send-verification-email", async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, message: "이메일을 입력해주세요." });
    }

    try {
        const pool = await sql.connect(dbConfig);
        const emailExists = await pool.request()
            .input("email", sql.NVarChar, email)
            .query("SELECT Email FROM Accounts WHERE Email = @email");

        if (emailExists.recordset.length > 0) {
            return res.status(400).json({ success: false, message: "이미 사용 중인 이메일입니다." });
        }
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        // 인증번호와 만료 시간(5분) 저장
        verificationCodes[email] = {
            code: code,
            expires: Date.now() + 5 * 60 * 1000 // 5분 후 만료
        };

        const mailOptions = {
            from: `"Titan" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: '[Titan] 회원가입 인증번호 안내',
            html: `<h1>회원가입 인증번호</h1><p>인증번호: <strong>${code}</strong></p><p>5분 내에 입력해주세요.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: "인증번호가 이메일로 발송되었습니다." });

    } catch (err) {
        console.error("이메일 발송 오류:", err);
        res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
});


/**
 * 이메일 인증번호 확인 API
 */
app.post("/verify-email-code", (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ success: false, message: "이메일과 인증번호를 모두 입력해주세요." });
    }

    const storedData = verificationCodes[email];

    if (!storedData) {
        return res.status(400).json({ success: false, message: "인증번호 요청 기록이 없습니다." });
    }

    if (Date.now() > storedData.expires) {
        delete verificationCodes[email]; // 만료된 코드는 삭제
        return res.status(400).json({ success: false, message: "인증번호가 만료되었습니다." });
    }

    if (storedData.code === code) {
        delete verificationCodes[email]; // 인증 성공 후 코드는 삭제
        res.json({ success: true, message: "이메일 인증 성공!" });
    } else {
        res.status(400).json({ success: false, message: "인증번호가 올바르지 않습니다." });
    }
});

// ▼▼▼ 이 부분을 추가하세요 ▼▼▼
/**
 * ID/PW 찾기 API (이메일로 계정 정보 및 임시 비밀번호 발송)
 */
app.post("/find-account", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "이메일을 입력해주세요." });

    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input("email", sql.NVarChar, email)
            .query("SELECT AccountId, Username FROM Accounts WHERE Email = @email");

        if (result.recordset.length === 0) {
            return res.status(404).json({ success: false, message: "해당 이메일로 가입된 계정이 없습니다." });
        }

        const user = result.recordset[0];
        const tempPassword = Math.random().toString(36).substring(2, 10); // 8자리 랜덤 문자열
        const hashedTempPassword = await bcrypt.hash(tempPassword, 10);

        // DB 비밀번호를 임시 비밀번호로 업데이트
        await pool.request()
            .input("accountId", sql.Int, user.AccountId)
            .input("passwordHash", sql.NVarChar, hashedTempPassword)
            .query("UPDATE Accounts SET PasswordHash = @passwordHash WHERE AccountId = @accountId");

        // 이메일 발송
        const mailOptions = {
            from: `"TITAN" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: '[TITAN] 계정 정보 및 임시 비밀번호 안내',
            html: `<h1>[TITAN] 계정 정보 안내</h1><p>안녕하세요, <strong>${user.Username}</strong>님!</p><p><strong>아이디:</strong> ${user.Username}</p><p><strong>임시 비밀번호:</strong> <h2>${tempPassword}</h2></p><p>로그인 후 반드시 비밀번호를 변경해주세요.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: "가입하신 이메일로 계정 정보와 임시 비밀번호를 발송했습니다." });

    } catch (err) {
        console.error("계정 찾기 서버 오류:", err);
        res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
});

/**
 * 비밀번호 변경 API (로그인 필요)
 */
app.post("/change-password", authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id; // authenticateToken에서 저장해준 사용자 ID

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ success: false, message: "현재 비밀번호와 새 비밀번호를 모두 입력해주세요." });
    }

    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input("accountId", sql.Int, userId)
            .query("SELECT PasswordHash FROM Accounts WHERE AccountId = @accountId");

        if (result.recordset.length === 0) {
            return res.status(404).json({ success: false, message: "사용자 정보를 찾을 수 없습니다." });
        }

        const user = result.recordset[0];

        const isMatch = await bcrypt.compare(currentPassword, user.PasswordHash);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "현재 비밀번호가 올바르지 않습니다." });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await pool.request()
            .input("accountId", sql.Int, userId)
            .input("newPasswordHash", sql.NVarChar, hashedNewPassword)
            .query("UPDATE Accounts SET PasswordHash = @newPasswordHash WHERE AccountId = @accountId");

        res.json({ success: true, message: "비밀번호가 성공적으로 변경되었습니다." });

    } catch (err) {
        console.error("비밀번호 변경 오류:", err);
        res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
