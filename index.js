require('dotenv').config(); // loads JWT_SECRET, etc.

const express = require('express');
const { expressjwt } = require('express-jwt');
const { Sequelize, UniqueConstraintError } = require('sequelize');

const dbConfig = require('./sequelize/config/config.js').development;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// 创建 Sequelize 实例,连接数据库
// const sequelize = new Sequelize(dbConfig.url, {
//     dialect: dbConfig.dialect,
//     dialectOptions: dbConfig.dialectOptions
// });

const sequelize = new Sequelize({
    database: dbConfig.database,
    username: dbConfig.username,
    password: dbConfig.password,
    host: dbConfig.host,
    port: dbConfig.port,
    dialect: dbConfig.dialect,
    dialectOptions: dbConfig.dialectOptions
    //logging: console.log // 可选：启用SQL查询日志
});
sequelize.sync();//auto migration on deploy

// 导入模型
const User = require('./sequelize/models/users.js')(sequelize, Sequelize.DataTypes);
const Password = require('./sequelize/models/userpassword.js')(sequelize, Sequelize.DataTypes);


// 初始化 Express 应用
const app = express();
const path = require('path');
const PORT = process.env.PORT || 3000;
//frontend talks to backend
const cors = require('cors');
app.use(cors());




// 加载静态页面
//app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json());//解析json请求
app.use(express.urlencoded({ extended: true }));// Body parsers for JSON and forms
//this is for html
//“如果用户请求 /、/signup.html、/login.html 或其他静态资源（JS、CSS、图片等），就去 public 文件夹里找这些文件。
//如果仅仅是/，就去index.html这个页面
// app.use(express.static('public'));

//console.log('DATABASE_URL:', process.env.DATABASE_URL);

app.use(
    expressjwt({
        secret: process.env.JWT_SECRET,   // the one you have
        algorithms: ['HS256'],
    }).unless({ path: ['/login', '/signup', '/'] })
);

// 测试连接
async function testConnection() {
    try {
        await sequelize.authenticate();
        console.log('Database connection has been established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

testConnection();

// ---- Auth helpers ----
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// 查询所有 Users 的接口
// app.get('/users', async (req, res) => {
//     try {
//         const users = await User.findAll();
//         res.json(users);
//     } catch (error) {
//         res.status(500).json({ error: 'Failed to fetch users', detail: error.message });
//     }
// });

function generateJWT(user) {
    return new Promise((resolve, reject) => {
        jwt.sign(
            { id: user.id, email: user.email }, // Payload
            process.env.JWT_SECRET,             // Secret key
            { algorithm: 'HS256', expiresIn: '1h' }, // Options
            (err, token) => {
                if (err) {
                    console.error("JWT Signing Error:", err);
                    return reject(err);
                }
                resolve(token);
            }
        );
    });
}

// POST 创建新 User
app.post('/signup', async (req, res) => {
    const { name, email, password, encryption_key } = req.body;
    try {
        const existing = await User.findOne({ where: { email } });
        if (existing) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedKey = await bcrypt.hash(encryption_key, 10);

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            encryption_key: hashedKey
        });

        res.status(201).json({
            message: 'Signup successfully'

        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Failed to sign up' });
    }
});

// Login: expects { email, password }
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email: email?.toLowerCase().trim() } });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid email or password' });

        const token = await generateJWT(user);

        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Failed to log in' });
    }
});

//save to the passwords table
app.post('/passwords/save', async (req, res) => {
    try {
        const { label, url, username, password, encryption_key } = req.body;
        const userId = req.auth && req.auth.id;

        if (!userId) {
            return res.status(401).json({ message: 'Not authenticated' });
        }
        //find the record according to the userId
        const userRecord = await User.findOne({
            attributes: ['encryption_key'],
            where: { id: userId }
        });
        if (!userRecord) {
            return res.status(403).json({ message: 'Unable to find the account' });
        }
        //compare the saved encryption_key with the user newly input one
        const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
        if (!matched) {
            return res.status(400).json({ message: 'Incorrect encryption key' });
        }

        if (!(username && password && url)) {
            return res.status(400).json({ message: 'Missing parameters' });
        }

        const encryptedUsername = encrypt(username, encryption_key);
        const encryptedPassword = encrypt(password, encryption_key);

        await Password.create({
            ownerUserId: userId,
            label,
            url,
            username: encryptedUsername,
            password: encryptedPassword
        });

        res.status(200).json({ message: 'Password is saved' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

//list all saved passwords
app.post('/passwords/list', async (req, res, next) => {
    try {
        const userId = req.auth.id;
        const encryptionKey = req.body.encryption_key;

        // 取用户加密密钥
        const userRecord = await User.findOne({
            attributes: ['encryption_key'],
            where: { id: userId }
        });

        if (!userRecord) {
            return res.status(403).json({ message: 'User not found' });
        }

        const matched = await bcrypt.compare(encryptionKey, userRecord.encryption_key);
        if (!matched) {
            return res.status(400).json({ message: 'Incorrect encryption key' });
        }

        // 查询当前用户所有密码
        let passwords = await Password.findAll({
            attributes: ['id', 'url', 'username', 'password', 'label'],
            where: { ownerUserId: userId }
        });

        // 解密
        const passwordsArr = passwords.map(p => {
            return {
                id: p.id,
                url: p.url,
                label: p.label,
                username: decrypt(p.username, encryptionKey),
                password: decrypt(p.password, encryptionKey)
            };
        });

        return res.status(200).json({ message: 'Success', data: passwordsArr });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});


//add this route to fix cannot get /（Render 会默认向你的服务器发送一个 GET 请求到 / 路由）
app.get('/', (req, res) => {
    res.send('Welcome to MyBuildProject_2025 API!');
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on port:${PORT}`);
});

function encrypt(unenrypted_string, key) {
    const algorithm = 'aes-256-ctr';
    const iv = crypto.randomBytes(16);
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
    const cipher = crypto.createCipheriv(algorithm, encKey, iv);
    let crypted = cipher.update(unenrypted_string, 'utf-8', 'base64') + cipher.final('base64');
    return `${crypted}-${iv.toString('base64')}`;
}

function decrypt(encStr, key) {
    const algorithm = 'aes-256-ctr';
    const encArr = encStr.split('-');
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
    const decipher = crypto.createDecipheriv(algorithm, encKey, Buffer.from(encArr[1], 'base64'));
    let decrypted = decipher.update(encArr[0], 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}