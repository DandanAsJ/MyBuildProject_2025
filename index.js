
const express = require('express');
const { Sequelize, UniqueConstraintError } = require('sequelize');
require('dotenv').config(); // loads JWT_SECRET, etc.
const dbConfig = require('./sequelize/config/config.js').development;


// 创建 Sequelize 实例,连接数据库
const sequelize = new Sequelize(dbConfig.url, {
    dialect: dbConfig.dialect,
    dialectOptions: dbConfig.dialectOptions
});

sequelize.sync();//auto migration on deploy

// 导入模型
const User = require('./sequelize/models/users.js')(sequelize, Sequelize.DataTypes);

// 初始化 Express 应用
const app = express();
const path = require('path');
const PORT = process.env.PORT || 3000;
//frontend talks to backend
const cors = require('cors');
app.use(cors());

const bcrypt = require('bcryptjs');

// 加载静态页面
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json());//解析json请求
app.use(express.urlencoded({ extended: true }));// Body parsers for JSON and forms

app.use(express.static('public'));

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
app.get('/users', async (req, res) => {
    try {
        const users = await User.findAll();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users', detail: error.message });
    }
});

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

// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on port:${PORT}`);
});
